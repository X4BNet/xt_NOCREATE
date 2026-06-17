#!/usr/bin/env python3
import argparse
import socket
import subprocess
import time


UDP_BASE_PORT = 41010
TCP_BASE_PORT = 42010
SSH_USER = "debian"
SSH_PASS = "asdfqwer"
REMOTE_HELPER = "/tmp/nocreate-ci-server.py"


class ScenarioError(Exception):
    pass


def ssh_root(vmip, script, timeout=20, check=True):
    proc = subprocess.run(
        [
            "sshpass",
            "-p",
            SSH_PASS,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
            f"{SSH_USER}@{vmip}",
            "sudo",
            "bash",
            "-s",
        ],
        input=script,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if check and proc.returncode != 0:
        raise ScenarioError(
            f"remote command failed with {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def install_remote_helper(vmip):
    helper = r'''#!/usr/bin/env python3
import argparse
import os
import socket
import sys


def mark_ready(path):
    if path:
        with open(path, "w", encoding="ascii") as ready:
            ready.write("ready\n")


def run_udp(args):
    if os.path.exists(args.output):
        os.unlink(args.output)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", args.port))
        sock.settimeout(args.timeout)
        mark_ready(args.ready)
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            data = b""
    with open(args.output, "wb") as out:
        out.write(data)
    return 0 if data else 2


def run_tcp(args):
    if os.path.exists(args.output):
        os.unlink(args.output)
    data = b""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", args.port))
        srv.listen(1)
        srv.settimeout(args.timeout)
        mark_ready(args.ready)
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            conn = None
        if conn is not None:
            with conn:
                conn.settimeout(args.timeout)
                data = conn.recv(4096)
                conn.sendall(b"nocreate-ok")
    with open(args.output, "wb") as out:
        out.write(data)
    return 0 if data else 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("protocol", choices=("udp", "tcp"))
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ready")
    parser.add_argument("--timeout", type=float, default=4.0)
    args = parser.parse_args()
    if args.protocol == "udp":
        return run_udp(args)
    return run_tcp(args)


if __name__ == "__main__":
    sys.exit(main())
'''
    ssh_root(
        vmip,
        f"cat > {REMOTE_HELPER} <<'PY'\n{helper}PY\nchmod +x {REMOTE_HELPER}\n",
    )


def cleanup(vmip):
    ssh_root(
        vmip,
        r'''
set +e
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
for port in $(seq 41010 41040); do
  while iptables -w -D INPUT -p udp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done
  iptables -w -t raw -D PREROUTING -p udp --dport "$port" -j NOCREATE 2>/dev/null
  iptables -w -t raw -D PREROUTING -p udp --dport "$port" -j NOCREATEA 2>/dev/null
  iptables -w -t raw -D PREROUTING -p udp --dport "$port" -j DROP 2>/dev/null
done
for port in $(seq 42010 42040); do
  while iptables -w -D INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done
  iptables -w -t mangle -D PREROUTING -p tcp --dport "$port" -j TCPCREATE 2>/dev/null
  iptables -w -t mangle -D PREROUTING -p tcp --dport "$port" -j TCPCREATEA 2>/dev/null
  iptables -w -t mangle -D PREROUTING -p tcp --dport "$port" -j DROP 2>/dev/null
done
for pidfile in /tmp/nocreate-ci-*.pid; do
  [ -e "$pidfile" ] || continue
  kill "$(cat "$pidfile")" 2>/dev/null
  rm -f "$pidfile"
done
rm -f /tmp/nocreate-ci-*.out /tmp/nocreate-ci-*.log /tmp/nocreate-ci-*.ready
conntrack -F >/dev/null 2>&1
true
''',
        timeout=20,
    )


def start_server(vmip, protocol, port, timeout=4.0):
    output = f"/tmp/nocreate-ci-{protocol}-{port}.out"
    pidfile = f"/tmp/nocreate-ci-{protocol}-{port}.pid"
    logfile = f"/tmp/nocreate-ci-{protocol}-{port}.log"
    readyfile = f"/tmp/nocreate-ci-{protocol}-{port}.ready"
    ssh_root(
        vmip,
        f'''
set -e
rm -f '{output}' '{pidfile}' '{logfile}' '{readyfile}'
nohup python3 '{REMOTE_HELPER}' '{protocol}' --port '{port}' --output '{output}' --ready '{readyfile}' --timeout '{timeout}' >'{logfile}' 2>&1 &
echo $! >'{pidfile}'
for _ in $(seq 1 50); do
  [ -s '{readyfile}' ] && exit 0
  if ! kill -0 "$(cat '{pidfile}')" 2>/dev/null; then
    cat '{logfile}' >&2 || true
    exit 1
  fi
  sleep 0.1
done
cat '{logfile}' >&2 || true
exit 1
''',
    )
    return output, pidfile, logfile


def stop_server(vmip, pidfile):
    ssh_root(
        vmip,
        f"if [ -f '{pidfile}' ]; then kill \"$(cat '{pidfile}')\" 2>/dev/null || true; rm -f '{pidfile}'; fi\n",
        check=False,
    )


def remote_file_bytes(vmip, path):
    proc = ssh_root(
        vmip,
        f"if [ -f '{path}' ]; then base64 -w0 '{path}'; fi\n",
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        return b""
    import base64

    return base64.b64decode(proc.stdout.strip())


def remote_file_text(vmip, path):
    return remote_file_bytes(vmip, path).decode("utf-8", errors="replace").strip()


def wait_for_payload(vmip, path, expected, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = remote_file_bytes(vmip, path)
        if observed == expected:
            return True
        time.sleep(0.2)
    return False


def send_udp(vmip, port, payload):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.0)
        sock.sendto(payload, (vmip, port))


def tcp_exchange(vmip, port, payload, timeout=2.0):
    try:
        with socket.create_connection((vmip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            return sock.recv(64)
    except OSError:
        return b""


def conntrack_has_udp(vmip, port):
    proc = ssh_root(
        vmip,
        f'''
conntrack -L -p udp 2>/dev/null | awk -v dport="{port}" '
  {{
    orig_dport = "";
    for (i = 1; i <= NF; i++) {{
      if ($i ~ /^dport=/) {{
        orig_dport = substr($i, 7);
        break;
      }}
    }}
    if (orig_dport == dport) {{
      found = 1;
    }}
  }}
  END {{
    exit found ? 0 : 1;
  }}'
''',
        check=False,
    )
    return proc.returncode == 0


def wait_for_udp_conntrack(vmip, port, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if conntrack_has_udp(vmip, port):
            return True
        time.sleep(0.2)
    return False


def conntrack_snapshot(vmip):
    proc = ssh_root(vmip, "conntrack -L 2>&1 || true\n", check=False)
    return proc.stdout.strip()


def iptables_snapshot(vmip):
    proc = ssh_root(vmip, "iptables-save 2>&1 || true\n", check=False)
    return proc.stdout.strip()


def flush_conntrack(vmip):
    ssh_root(vmip, "conntrack -F >/dev/null 2>&1 || true\n", check=False)


def add_raw_rules(vmip, port, first_target=None, drop_after=False):
    lines = ["set -e", "export PATH=/usr/sbin:/sbin:/usr/bin:/bin"]
    lines.append(f"iptables -w -I INPUT 1 -p udp --dport {port} -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT")
    if drop_after:
      lines.append(f"iptables -w -t raw -I PREROUTING 1 -p udp --dport {port} -j DROP")
    if first_target:
      lines.append(f"iptables -w -t raw -I PREROUTING 1 -p udp --dport {port} -j {first_target}")
    ssh_root(vmip, "\n".join(lines) + "\n")


def add_mangle_rules(vmip, port, first_target, drop_after=True):
    lines = ["set -e", "export PATH=/usr/sbin:/sbin:/usr/bin:/bin"]
    lines.append(f"iptables -w -I INPUT 1 -p tcp --dport {port} -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT")
    if drop_after:
      lines.append(f"iptables -w -t mangle -I PREROUTING 1 -p tcp --dport {port} -j DROP")
    lines.append(f"iptables -w -t mangle -I PREROUTING 1 -p tcp --dport {port} -j {first_target}")
    ssh_root(vmip, "\n".join(lines) + "\n")


def run_udp_case(vmip, name, offset, target=None, drop_after=False, expect_delivery=True, expect_conntrack=False):
    port = UDP_BASE_PORT + offset
    payload = f"{name}-payload".encode("ascii")
    cleanup(vmip)
    flush_conntrack(vmip)
    add_raw_rules(vmip, port, first_target=target, drop_after=drop_after)
    output, pidfile, _ = start_server(vmip, "udp", port)
    send_udp(vmip, port, payload)
    delivered = wait_for_payload(vmip, output, payload, timeout=4.5)
    stop_server(vmip, pidfile)
    if delivered != expect_delivery:
        raise ScenarioError(f"{name}: delivery={delivered}, expected {expect_delivery}")
    has_ct = wait_for_udp_conntrack(vmip, port) if expect_conntrack else conntrack_has_udp(vmip, port)
    if has_ct != expect_conntrack:
        raise ScenarioError(
            f"{name}: conntrack={has_ct}, expected {expect_conntrack}\n"
            f"conntrack table:\n{conntrack_snapshot(vmip)}"
        )
    print(f"{name}: ok")


def run_tcp_case(vmip, name, offset, target, expect_delivery):
    port = TCP_BASE_PORT + offset
    payload = f"{name}-payload".encode("ascii")
    cleanup(vmip)
    add_mangle_rules(vmip, port, first_target=target)
    output, pidfile, logfile = start_server(vmip, "tcp", port)
    ack = tcp_exchange(vmip, port, payload)
    delivered = ack == b"nocreate-ok" and wait_for_payload(vmip, output, payload, timeout=2.0)
    stop_server(vmip, pidfile)
    if delivered != expect_delivery:
        raise ScenarioError(
            f"{name}: tcp delivery={delivered}, expected {expect_delivery}\n"
            f"server log:\n{remote_file_text(vmip, logfile)}\n"
            f"iptables:\n{iptables_snapshot(vmip)}\n"
            f"conntrack table:\n{conntrack_snapshot(vmip)}"
        )
    print(f"{name}: ok")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("vmip")
    parser.add_argument("gwip", nargs="?")
    args = parser.parse_args()

    install_remote_helper(args.vmip)
    cleanup(args.vmip)
    try:
        run_udp_case(args.vmip, "baseline-udp-creates-conntrack", 0, expect_delivery=True, expect_conntrack=True)
        run_udp_case(args.vmip, "nocreate-udp-suppresses-conntrack", 1, target="NOCREATE", expect_delivery=True, expect_conntrack=False)
        run_udp_case(args.vmip, "nocreate-continues-to-drop", 2, target="NOCREATE", drop_after=True, expect_delivery=False, expect_conntrack=False)
        run_udp_case(args.vmip, "nocreatea-accepts-before-drop", 3, target="NOCREATEA", drop_after=True, expect_delivery=True, expect_conntrack=False)
        run_tcp_case(args.vmip, "tcpcreate-continues-to-drop", 0, "TCPCREATE", expect_delivery=False)
        run_tcp_case(args.vmip, "tcpcreatea-accepts-before-drop", 1, "TCPCREATEA", expect_delivery=True)
    finally:
        cleanup(args.vmip)


if __name__ == "__main__":
    main()

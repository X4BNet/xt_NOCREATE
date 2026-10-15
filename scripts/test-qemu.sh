#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

usage() {
  cat <<'EOF'
Usage: ./scripts/test-qemu.sh [options]

Options:
  --skip-local-build  Skip the local host build step even if the current host kernel tree is compatible.
  --keep-workdir      Preserve the temporary QEMU workspace.
  --help              Show this help text.

Environment:
  KERNEL_MODULE_CI_ROOT
                      Path to shared kernel-module-ci checkout. Default: ci/kernel-module-ci, then ../kernel-module-ci
  KMOD_CI_RTS_ROOT    Optional local xt_RTS checkout. Defaults to ../xt_RTS
                      when that sibling checkout is present.
  X4B_KERNEL_ARTIFACT_DIR
                      Path to a prebuilt kernel artifact directory. Default: use /runner/kernel cache
  VMIP                Preferred guest IPv4 address; falls back if occupied.
  X4B_QEMU_SUBNET_POOL
                      Allocation pool. Default: 192.168.224.0/19
  X4B_QEMU_SUBNET_PREFIX
                      Per-run prefix. Default: 24
  X4B_QEMU_STRICT_VMIP
                      Set to 1 to require the preferred VMIP.
EOF
}

if [[ "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

resolve_dir() {
  local input="$1"

  (cd "$input" 2>/dev/null && pwd)
}

resolve_shared_root() {
  local input="${KERNEL_MODULE_CI_ROOT:-$REPO_ROOT/ci/kernel-module-ci}"
  local root

  if root="$(resolve_dir "$input")" && [[ -x "$root/scripts/test-qemu.sh" ]]; then
    echo "$root"
    return 0
  fi

  if root="$(resolve_dir "$REPO_ROOT/../kernel-module-ci")" && [[ -x "$root/scripts/test-qemu.sh" ]]; then
    echo "$root"
    return 0
  fi

  echo "error: missing shared kernel-module-ci checkout; set KERNEL_MODULE_CI_ROOT or initialize ci/kernel-module-ci" >&2
  exit 1
}

if [[ ! -x "$REPO_ROOT/build.sh" ]]; then
  echo "error: missing executable build script at $REPO_ROOT/build.sh" >&2
  exit 1
fi

SHARED_ROOT="$(resolve_shared_root)"

if [[ -z "${KMOD_CI_RTS_ROOT:-}" && -f "$REPO_ROOT/../xt_RTS/src/xt_RTS.c" ]]; then
  export KMOD_CI_RTS_ROOT="$REPO_ROOT/../xt_RTS"
fi

export KMOD_CI_MODULE_NAME="xt-nocreate"
export KMOD_CI_ENV_NAME="nocreate-local"
export KMOD_CI_REPO_ROOT="$REPO_ROOT"
export KMOD_CI_PACKETS_DIR="$REPO_ROOT/scripts/qemu/nocreate-local-packets"
export KMOD_CI_HOST_BUILD_COMMAND='
if grep -R -q "IPS_NOCREATE_BIT" "/lib/modules/$(uname -r)/build/include" 2>/dev/null; then
  ./build.sh
else
  echo "Skipping local host build because $(uname -r) does not expose the custom NOCREATE kernel patch; the guest build will use the custom kernel flow instead."
fi
'

exec "$SHARED_ROOT/scripts/test-qemu.sh" "$@"

# xt_NOCREATE Agent Notes

## Local build

Run the host build from the repo root:

```sh
./build.sh
```

Useful variants:

```sh
./build.sh --deps-only
./build.sh --configure-only
./build.sh --clean
./build.sh --kver "$(uname -r)"
./build.sh --kver "$(uname -r)" --kdir "/lib/modules/$(uname -r)/build"
```

The supported host target is Debian/Ubuntu with `apt`. The default build is
non-installing: it regenerates `src/Makefile`, then builds the kernel module
and xtables userspace libraries in `src/`.

`xt_NOCREATE` requires an X4B-patched kernel tree that exposes
`IPS_NOCREATE_BIT`. A stock distro kernel headers package is not enough by
itself; point `./build.sh` at a prepared patched kernel build tree with
`--kdir`, or use the QEMU flow below to build against the patched guest kernel
artifacts.

## QEMU test flow

Prerequisites:

- shared `ci/kernel-module-ci` submodule, or sibling `../kernel-module-ci` checkout
- Docker on the host
- `sudo` on the host
- default or explicit guest IP via `VMIP`

The shared QEMU harness creates a Docker bridge subnet from `VMIP` using a
`/21`, so `VMIP` must not overlap Docker address pools or host routes.
`192.168.224.2` is the known-good default used by CI; avoid `172.17.*` on
runners with Docker's default bridge.

Run the CI-parity guest build and packet-test flow from the repo root:

```sh
VMIP=192.168.224.2 ./scripts/test-qemu.sh
```

Useful variants:

```sh
./scripts/test-qemu.sh --skip-local-build
./scripts/test-qemu.sh --keep-workdir
X4B_KERNEL_ARTIFACT_DIR=/path/to/kernel-patches/artifacts/6.1.106 VMIP=192.168.224.2 ./scripts/test-qemu.sh
KERNEL_MODULE_CI_ROOT=/path/to/kernel-module-ci VMIP=192.168.224.2/24 ./scripts/test-qemu.sh
```

The QEMU harness delegates shared Docker, patched-kernel, reboot, and guest
lifecycle work to `kernel-module-ci`, while this repository keeps the
NOCREATE setup, smoke tests, and packet tests under `scripts/qemu/`. The module
checkout is mounted at `/module-src` so uncommitted local changes are tested.
When `X4B_KERNEL_ARTIFACT_DIR` is set, the harness skips the shared
`/runner/kernel` download cache and mounts the provided local kernel artifact
set at `/root/kernel` instead.

## Architecture map

- `src/xt_NOCREATE.c`: kernel target module implementing `NOCREATE`,
  `NOCREATEA`, `TCPCREATE`, and `TCPCREATEA`.
- `src/xt_NOCREATE.h`: shared target info structure consumed by the kernel
  module and xtables plugins.
- `src/libxt_NOCREATE*.c` and `src/libxt_TCPCREATE*.c`: xtables userspace
  target plugins.
- `src/configure` and `src/Makefile.in`: legacy configure/build flow used by
  local builds and Ansible.
- `patches/`: legacy kernel patch reference for older kernels.
- `ansible/`: deployment role consumed by `x4b-ansible` as a submodule role.

## Style and change rules

- Preserve the existing low-churn legacy C style in kernel and xtables files.
  Match nearby formatting and naming instead of normalizing old code wholesale.
- Prefer the smallest compatibility fix that restores the current build on the
  target kernel. Fix build/configuration glue before changing conntrack
  behavior.
- Keep host build automation in `build.sh`; keep guest test orchestration in
  `scripts/test-qemu.sh`; keep module-specific guest tests in `scripts/qemu/`.
- Keep source files under `src/`; adapt wrappers and scripts around that layout
  rather than relocating the module.
- Keep the QEMU local setup building from `/module-src` so uncommitted local
  changes are tested instead of the remote GitHub branch.

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
cd "$SCRIPT_DIR"

usage() {
  cat <<'EOF'
Usage: ./build.sh [options]

Options:
  --deps-only        Install missing host dependencies and exit.
  --configure-only   Run src/configure and exit before make.
  --clean            Remove generated build artifacts.
  --kver <release>   Build for this kernel release. Defaults to `uname -r`.
  --kdir <path>      Use this prepared kernel build tree.
  --help             Show this help text.

xt_NOCREATE only builds against a kernel tree with the X4B NOCREATE
conntrack patch applied.
EOF
}

find_kernel_headers() {
  local search_root="$1"
  local header="$2"

  find "$search_root" -path "*/include/*/linux/netfilter/${header}" -o \
    -path "*/include/linux/netfilter/${header}" 2>/dev/null
}

require_nocreate_kernel_tree() {
  local dir="$1"
  local resolved_dir found header search_root

  resolved_dir="$(readlink -f "$dir" 2>/dev/null || printf '%s\n' "$dir")"
  found=0

  for search_root in "$resolved_dir" "$(dirname "$resolved_dir")"; do
    [[ -d "$search_root" ]] || continue
    while IFS= read -r header; do
      found=1
      if grep -q 'IPS_NOCREATE_BIT' "$header"; then
        return 0
      fi
    done < <(find_kernel_headers "$search_root" nf_conntrack_common.h)
  done

  if [[ "$found" -eq 0 ]]; then
    cat >&2 <<EOF
error: unable to inspect netfilter headers under kernel tree '$dir' to verify NOCREATE support.

Use a prepared kernel build tree that includes the X4B NOCREATE patch, or run
./scripts/test-qemu.sh with X4B_KERNEL_ARTIFACT_DIR pointing at patched kernel
artifacts.
EOF
    exit 1
  fi

  cat >&2 <<EOF
error: kernel tree '$dir' does not contain IPS_NOCREATE_BIT.

xt_NOCREATE does not build against an unpatched stock kernel tree. Use a
prepared kernel build tree that includes the X4B NOCREATE patch set.
EOF
  exit 1
}

require_apt_host() {
  if [[ ! -r /etc/os-release ]]; then
    echo "error: unsupported host: /etc/os-release is missing" >&2
    exit 1
  fi

  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    debian|ubuntu)
      ;;
    *)
      echo "error: unsupported host '${ID:-unknown}'; build.sh only supports Debian/Ubuntu apt-based environments" >&2
      exit 1
      ;;
  esac

  if ! command -v apt-get >/dev/null 2>&1; then
    echo "error: unsupported host: apt-get is required" >&2
    exit 1
  fi
}

validate_prepared_kdir() {
  local dir="$1"
  [[ -n "$dir" ]] || return 1
  [[ -f "$dir/include/config/kernel.release" ]]
}

install_missing_packages() {
  local packages=("$@")
  local missing=()
  local pkg

  for pkg in "${packages[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    echo "All required packages are already installed."
    return 0
  fi

  echo "Installing missing packages: ${missing[*]}"
  sudo apt-get update
  sudo apt-get install -y "${missing[@]}"
}

clean_generated_files() {
  local generated=(
    Makefile
    Module.symvers
    modules.order
    .tmp_versions
    cc-test-build
  )

  if [[ -f "$SRC_DIR/Makefile" ]]; then
    make -C "$SRC_DIR" clean || true
  fi

  (
    cd "$SRC_DIR"
    rm -rf "${generated[@]}"
    rm -f -- *.ko *.so *.o *_sh.o *.cmd .*.cmd .*.o .*.o.d *.mod *.mod.c *.mod.o
  )
}

DEPS_ONLY=0
CONFIGURE_ONLY=0
CLEAN_ONLY=0
KVER="$(uname -r)"
KDIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deps-only)
      DEPS_ONLY=1
      shift
      ;;
    --configure-only)
      CONFIGURE_ONLY=1
      shift
      ;;
    --clean)
      CLEAN_ONLY=1
      shift
      ;;
    --kver)
      [[ $# -ge 2 ]] || { echo "error: --kver requires a value" >&2; exit 1; }
      KVER="$2"
      shift 2
      ;;
    --kver=*)
      KVER="${1#*=}"
      shift
      ;;
    --kdir)
      [[ $# -ge 2 ]] || { echo "error: --kdir requires a value" >&2; exit 1; }
      KDIR="$2"
      shift 2
      ;;
    --kdir=*)
      KDIR="${1#*=}"
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$CLEAN_ONLY" -eq 1 ]]; then
  clean_generated_files
  exit 0
fi

if [[ ! -x "$SRC_DIR/configure" || ! -f "$SRC_DIR/Makefile.in" ]]; then
  echo "error: build.sh must run from the xt_NOCREATE repo root containing executable src/configure and src/Makefile.in" >&2
  exit 1
fi

require_apt_host

if [[ -n "$KDIR" ]]; then
  if ! validate_prepared_kdir "$KDIR"; then
    echo "error: kernel build tree '$KDIR' is not prepared; missing $KDIR/include/config/kernel.release for kernel release $KVER" >&2
    exit 1
  fi
fi

DEFAULT_KERNEL_RELEASE_PATH="/lib/modules/$KVER/build/include/config/kernel.release"
HEADER_PACKAGE="linux-headers-$KVER"
PACKAGES=(build-essential git iptables libxtables-dev pkg-config)

if [[ -z "$KDIR" && ! -f "$DEFAULT_KERNEL_RELEASE_PATH" ]]; then
  PACKAGES+=("$HEADER_PACKAGE")
fi

install_missing_packages "${PACKAGES[@]}"

if [[ "$DEPS_ONLY" -eq 1 ]]; then
  exit 0
fi

if [[ -z "$KDIR" ]]; then
  if [[ ! -f "$DEFAULT_KERNEL_RELEASE_PATH" ]]; then
    if ! apt-cache policy "$HEADER_PACKAGE" 2>/dev/null | grep -q 'Candidate:' ||
       apt-cache policy "$HEADER_PACKAGE" 2>/dev/null | grep -q 'Candidate: (none)'; then
      echo "error: missing prepared kernel tree $DEFAULT_KERNEL_RELEASE_PATH for kernel release $KVER, and package $HEADER_PACKAGE is unavailable" >&2
      exit 1
    fi
    echo "error: missing prepared kernel tree $DEFAULT_KERNEL_RELEASE_PATH for kernel release $KVER after installing $HEADER_PACKAGE" >&2
    exit 1
  fi
fi

if [[ -n "$KDIR" ]]; then
  require_nocreate_kernel_tree "$KDIR"
else
  require_nocreate_kernel_tree "/lib/modules/$KVER/build"
fi

CONFIGURE_ARGS=("--disable-dkms" "--kver=$KVER")

if [[ -n "$KDIR" ]]; then
  CONFIGURE_ARGS+=("--kdir=$KDIR")
fi

echo "Running configure for kernel release $KVER"
(
  cd "$SRC_DIR"
  ./configure "${CONFIGURE_ARGS[@]}"
)

if [[ "$CONFIGURE_ONLY" -eq 1 ]]; then
  exit 0
fi

echo "Building module and userspace artifacts"
make -C "$SRC_DIR" all

echo "Produced artifacts:"
for artifact in \
  src/Makefile \
  src/xt_NOCREATE.ko \
  src/libxt_NOCREATE.so \
  src/libxt_NOCREATEA.so \
  src/libxt_TCPCREATE.so \
  src/libxt_TCPCREATEA.so
do
  if [[ -e "$artifact" ]]; then
    printf '  %s\n' "$artifact"
  fi
done

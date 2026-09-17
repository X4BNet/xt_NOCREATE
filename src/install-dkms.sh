#!/usr/bin/env bash
# Cleanly reinstall the module into the DKMS tree.

set -euo pipefail

PATH=$PATH:/bin:/usr/bin:/usr/sbin:/sbin:/usr/local/sbin
MODULE_NAME=xt-nocreate
TARGET_KERNEL="${KVERSION:-}"

case "${1:-}" in
  --install|--uninstall) ;;
  *) exit 1 ;;
esac

if ! command -v dkms >/dev/null 2>&1; then
  echo "! You don't have DKMS accessible in system."
  exit 1
fi

MVERSION="$(./version.sh)"
declare -A versions=()
for path in /usr/src/${MODULE_NAME}-*; do
  [[ -d "$path" ]] && versions["${path#/usr/src/${MODULE_NAME}-}"]=1
done
while IFS= read -r line; do
  version="$(printf '%s' "$line" | sed -n "s#^${MODULE_NAME}[/,[:space:]]*\\([^,[:space:]]*\\).*#\\1#p")"
  [[ -n "$version" ]] && versions["$version"]=1
done < <(dkms status | grep "^${MODULE_NAME}" || true)

nodepmod=
grep -qs no-depmod "$(command -v dkms)" && nodepmod=--no-depmod
for version in "${!versions[@]}"; do
  [[ "$1" == "--install" && "$version" == "$MVERSION" ]] && continue
  echo "! Removing existing ${MODULE_NAME}/$version from DKMS..."
  dkms $nodepmod remove "${MODULE_NAME}/$version" --all || true
  rm -rf "/usr/src/${MODULE_NAME}-$version"
done

[[ "$1" == "--uninstall" ]] && exit 0
if [[ -z "$TARGET_KERNEL" ]]; then
  echo "! KVERSION must identify the target kernel."
  exit 1
fi

install_root="/usr/src/${MODULE_NAME}-$MVERSION"
rm -rf "$install_root"
mkdir -p "$install_root"
cp -a . "$install_root/"
rm -f "$install_root"/Makefile "$install_root"/Module.symvers "$install_root"/modules.order
find "$install_root" -type f \( -name '*.ko' -o -name '*.o' -o -name '*.so' -o -name '*.cmd' -o -name '.*.cmd' -o -name '.*.o.d' -o -name '*.mod' -o -name '*.mod.c' -o -name '*.mod.o' \) -delete
printf '%s\n' "$MVERSION" > "$install_root/.module-version"
touch "$install_root/.automatic"

if ! dkms status "${MODULE_NAME}/$MVERSION" 2>/dev/null | grep -q "^${MODULE_NAME}"; then
  dkms add -m "$MODULE_NAME" -v "$MVERSION"
fi
dkms $nodepmod remove "${MODULE_NAME}/$MVERSION" -k "$TARGET_KERNEL" >/dev/null 2>&1 || true
dkms build -m "$MODULE_NAME" -v "$MVERSION" -k "$TARGET_KERNEL"
dkms install -m "$MODULE_NAME" -v "$MVERSION" -k "$TARGET_KERNEL"

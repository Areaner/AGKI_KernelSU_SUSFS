#!/bin/sh
set -eu

GKI_ROOT="$(pwd)"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/xingguang-ddk"
PATCH_DIR="$SCRIPT_DIR/patches/xingguang-ddk"
DDK_DIR="$GKI_ROOT/Xingguang-DDK"

if [ -d "$GKI_ROOT/security" ]; then
	COMMON_ROOT="$GKI_ROOT"
	SECURITY_DIR="$GKI_ROOT/security"
elif [ -d "$GKI_ROOT/common/security" ]; then
	COMMON_ROOT="$GKI_ROOT/common"
	SECURITY_DIR="$GKI_ROOT/common/security"
else
	echo '[ERROR] security directory not found.'
	exit 127
fi

SECURITY_MAKEFILE="$SECURITY_DIR/Makefile"
SECURITY_KCONFIG="$SECURITY_DIR/Kconfig"
DDK_SYMLINK="$SECURITY_DIR/xingguang-ddk"

if [ ! -d "$SRC_DIR" ]; then
	echo "[ERROR] DDK source directory not found: $SRC_DIR"
	exit 127
fi

echo "[+] Setting up Xingguang DDK LSM"

if [ -d "$PATCH_DIR" ]; then
	echo "[+] Applying Xingguang DDK patch stack"
	for patch in "$PATCH_DIR"/*.patch; do
		[ -e "$patch" ] || continue
		name="$(basename "$patch")"
		optional=false
		case "$name" in
			*.optional.patch) optional=true ;;
		esac
		if git -C "$COMMON_ROOT" apply --check "$patch" >/dev/null 2>&1; then
			git -C "$COMMON_ROOT" apply "$patch"
			echo " - applied $name"
		elif git -C "$COMMON_ROOT" apply --reverse --check "$patch" >/dev/null 2>&1; then
			echo " - already applied $name"
		elif [ "$optional" = true ]; then
			echo " - skipped optional $name"
		else
			echo "[ERROR] failed to apply DDK patch: $patch"
			git -C "$COMMON_ROOT" apply --check "$patch"
			exit 1
		fi
	done
fi

rm -rf "$DDK_DIR"
mkdir -p "$DDK_DIR"
cp -a "$SRC_DIR/." "$DDK_DIR/"

cd "$SECURITY_DIR"
if command -v realpath >/dev/null 2>&1; then
	rel="$(realpath --relative-to="$SECURITY_DIR" "$DDK_DIR" 2>/dev/null || true)"
else
	rel="$DDK_DIR"
fi
[ -n "$rel" ] || rel="$DDK_DIR"
ln -sfn "$rel" "$DDK_SYMLINK"

if ! grep -q 'xingguang-ddk' "$SECURITY_MAKEFILE"; then
	printf '\nobj-$(CONFIG_XINGGUANG_DDK) += xingguang-ddk/\n' >> "$SECURITY_MAKEFILE"
	echo " - Makefile updated"
fi

if ! grep -q 'security/xingguang-ddk/Kconfig' "$SECURITY_KCONFIG"; then
	if grep -n '^endmenu[[:space:]]*$' "$SECURITY_KCONFIG" >/dev/null 2>&1; then
		awk '
			{ a[NR]=$0 }
			END {
				last=0
				for (i=1; i<=NR; i++) if (a[i] ~ /^endmenu[[:space:]]*$/) last=i
				for (i=1; i<=NR; i++) {
					if (i==last) print "source \"security/xingguang-ddk/Kconfig\""
					print a[i]
				}
			}
		' "$SECURITY_KCONFIG" > "$SECURITY_KCONFIG.tmp" && mv "$SECURITY_KCONFIG.tmp" "$SECURITY_KCONFIG"
	else
		printf '\nsource "security/xingguang-ddk/Kconfig"\n' >> "$SECURITY_KCONFIG"
	fi
	echo " - Kconfig updated"
fi

sed -i '/^config LSM$/,/^help$/{ /^[[:space:]]*default/ { /xingguang_ddk/! s/selinux/selinux,xingguang_ddk/ } }' "$SECURITY_KCONFIG"

echo "[+] Xingguang DDK LSM ready."

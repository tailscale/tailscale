#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# gokrazy-debug-kernel.sh builds a debug variant of a gokrazy kernel package's
# kernel (see gokrazy-kdir.sh): the same release, patches and config, plus
# KASAN, lockdep, DEBUG_VM and DEBUG_NET, for catching memory and locking
# bugs in tswg. It prints the build directory to stdout; the kernel is
# arch/x86/boot/bzImage there, and tswg.ko must be built against that
# directory (TSWG_KDIR=... build-for-gokrazy.sh), since the debug options
# change kernel data structures.
#
# Results are cached in $TSLINUX_CACHE (default ~/.cache/tslinux).
#
# usage: gokrazy-debug-kernel.sh GOKRAZY_KERNEL_PACKAGE_DIR

set -eu

if [ $# -ne 1 ]; then
	echo "usage: $0 GOKRAZY_KERNEL_PACKAGE_DIR" >&2
	exit 2
fi
pkg=$1
cache=${TSLINUX_CACHE:-$HOME/.cache/tslinux}

url=$(cat "$pkg/_build/upstream-url.txt")
tarball=${url##*/}
srcname=${tarball%.tar.*}

config=$(mktemp)
trap 'rm -f "$config"' EXIT
"$(dirname "$0")/extract-ikconfig" "$pkg/vmlinuz" > "$config"
hash=$(sha256sum "$config" "$0" | sha256sum | cut -c1-12)

kdir=$cache/gokrazy/$srcname-$hash-debug
if [ -f "$kdir/.tswg-built" ]; then
	echo "$kdir"
	exit 0
fi

mkdir -p "$cache/tarballs"
if [ ! -f "$cache/tarballs/$tarball" ]; then
	echo "downloading $url" >&2
	curl -sSfL -o "$cache/tarballs/$tarball.tmp" "$url"
	mv "$cache/tarballs/$tarball.tmp" "$cache/tarballs/$tarball"
fi

rm -rf "$kdir"
mkdir -p "$kdir"
echo "unpacking $tarball" >&2
tar -xf "$cache/tarballs/$tarball" -C "$kdir" --strip-components=1
if [ -f "$pkg/_build/series" ]; then
	while read -r patch; do
		[ -n "$patch" ] || continue
		patch -s -d "$kdir" -p1 < "$pkg/_build/$patch"
	done < "$pkg/_build/series"
fi
cp "$config" "$kdir/.config"
"$kdir/scripts/config" --file "$kdir/.config" \
	-e DEBUG_KERNEL \
	-e KASAN -e KASAN_GENERIC -e KASAN_INLINE \
	-e PROVE_LOCKING -e DEBUG_ATOMIC_SLEEP \
	-e DEBUG_VM -e DEBUG_NET \
	-d DEBUG_INFO_BTF -d RANDOMIZE_BASE
echo "building debug $srcname" >&2
make -s -C "$kdir" olddefconfig >&2
make -s -C "$kdir" -j"$(nproc)" bzImage modules_prepare >&2
touch "$kdir/.tswg-built"
echo "$kdir"

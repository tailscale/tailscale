#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# gokrazy-kdir.sh prepares a kernel build directory matching a gokrazy
# kernel package (such as the github.com/gokrazy/kernel.amd64 module that
# tailscale.com's natlab gokrazy image uses) and prints its path to stdout.
#
# gokrazy kernels are upstream kernel.org releases plus the patches listed in
# _build/series, and embed their .config (CONFIG_IKCONFIG). So we download
# that release, apply the patches, install the embedded config and run
# "make modules_prepare". That's enough to build tswg.ko for that kernel,
# since gokrazy kernels don't use MODVERSIONS or module signing.
#
# Results are cached in $TSLINUX_CACHE (default ~/.cache/tslinux), keyed by
# the kernel release and a hash of the config.
#
# usage: gokrazy-kdir.sh GOKRAZY_KERNEL_PACKAGE_DIR

set -eu

if [ $# -ne 1 ]; then
	echo "usage: $0 GOKRAZY_KERNEL_PACKAGE_DIR" >&2
	exit 2
fi
pkg=$1
cache=${TSLINUX_CACHE:-$HOME/.cache/tslinux}

url=$(cat "$pkg/_build/upstream-url.txt")
tarball=${url##*/}         # linux-7.2.8.tar.xz
srcname=${tarball%.tar.*}  # linux-7.2.8

config=$(mktemp)
trap 'rm -f "$config"' EXIT
"$(dirname "$0")/extract-ikconfig" "$pkg/vmlinuz" > "$config"
hash=$(sha256sum "$config" | cut -c1-12)

kdir=$cache/gokrazy/$srcname-$hash
if [ -f "$kdir/.tswg-prepared" ]; then
	echo "$kdir"
	exit 0
fi

mkdir -p "$cache/tarballs"
if [ ! -f "$cache/tarballs/$tarball" ]; then
	echo "downloading $url" >&2
	curl -sSfL -o "$cache/tarballs/$tarball.tmp" "$url"
	mv "$cache/tarballs/$tarball.tmp" "$cache/tarballs/$tarball"
fi

# Build in place (kbuild state records absolute paths, so the tree can't
# be moved afterwards) and mark it complete at the end.
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
echo "preparing $srcname for modules" >&2
make -s -C "$kdir" olddefconfig >&2
make -s -C "$kdir" -j"$(nproc)" modules_prepare >&2
touch "$kdir/.tswg-prepared"
echo "$kdir"

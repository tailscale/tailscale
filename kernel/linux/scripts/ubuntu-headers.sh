#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# ubuntu-headers.sh fetches and unpacks (without installing) the Ubuntu
# kernel headers for the given kernel release, such as 6.8.0-106-generic,
# and prints the resulting kernel build directory to stdout.
#
# It uses "apt-get download", so the host's apt sources must carry that
# kernel version. Results are cached in $TSLINUX_CACHE (default
# ~/.cache/tslinux).

set -eu

if [ $# -ne 1 ]; then
	echo "usage: $0 <kernel-release, e.g. 6.8.0-106-generic>" >&2
	exit 2
fi
kver=$1
flavor=${kver##*-}        # generic
base=${kver%-"$flavor"}   # 6.8.0-106

cache=${TSLINUX_CACHE:-$HOME/.cache/tslinux}
root=$cache/headers/$kver
build=$root/usr/src/linux-headers-$kver

if [ -f "$build/Makefile" ]; then
	echo "$build"
	exit 0
fi

debs=$cache/debs
mkdir -p "$debs"
(cd "$debs" && apt-get download -q "linux-headers-$kver" "linux-headers-$base" >&2)

tmp=$root.tmp
rm -rf "$tmp"
mkdir -p "$tmp"
for deb in "$debs"/linux-headers-"$kver"_*.deb "$debs"/linux-headers-"$base"_*.deb; do
	dpkg-deb -x "$deb" "$tmp"
done
rm -rf "$root"
mv "$tmp" "$root"
echo "$build"

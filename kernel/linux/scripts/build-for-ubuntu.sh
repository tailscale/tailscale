#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# build-for-ubuntu.sh builds tswg.ko for the given Ubuntu kernel release
# (such as 6.8.0-106-generic) in a private copy of src/ under OUTDIR, and
# prints the path of the resulting tswg.ko to stdout. All build output goes
# to stderr.
#
# usage: build-for-ubuntu.sh KERNEL_RELEASE OUTDIR

set -eu

if [ $# -ne 2 ]; then
	echo "usage: $0 KERNEL_RELEASE OUTDIR" >&2
	exit 2
fi
kver=$1
out=$2
top=$(cd "$(dirname "$0")/.." && pwd)

kdir=$("$top/scripts/ubuntu-headers.sh" "$kver")

mkdir -p "$out"
rm -rf "$out/src"
cp -r "$top/src" "$out/src"
make -C "$top" KDIR="$kdir" SRC="$out/src" >&2
echo "$out/src/tswg.ko"

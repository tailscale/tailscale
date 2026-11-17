#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# build.sh builds tswg.ko against the kernel build directory KDIR in a
# private copy of src/ under OUTDIR, and prints the path of the resulting
# tswg.ko to stdout. All build output goes to stderr.
#
# usage: build.sh KDIR OUTDIR

set -eu

if [ $# -ne 2 ]; then
	echo "usage: $0 KDIR OUTDIR" >&2
	exit 2
fi
kdir=$1
out=$2
top=$(cd "$(dirname "$0")/.." && pwd)

# Copy only sources, not any objects from an in-place build in src/.
mkdir -p "$out"
rm -rf "$out/src"
tar -C "$top" -cf - \
	--exclude='*.o' --exclude='*.ko' --exclude='*.mod' --exclude='*.mod.c' \
	--exclude='*.cmd' --exclude='*.o.d' --exclude=modules.order \
	--exclude=Module.symvers --exclude=generated/autoconf.h \
	src | tar -C "$out" -xf -

# A tree prepared with "make modules_prepare" (as for gokrazy kernels) has
# no Module.symvers, so modpost can't resolve the kernel's exports. That's
# fine without MODVERSIONS; unresolved symbols then show up at load time.
modpost_warn=
if [ ! -f "$kdir/Module.symvers" ]; then
	modpost_warn=KBUILD_MODPOST_WARN=1
fi

make -C "$top" KDIR="$kdir" SRC="$out/src" $modpost_warn >&2
echo "$out/src/tswg.ko"

#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# build-for-gokrazy.sh builds tswg.ko for a gokrazy kernel package (see
# gokrazy-kdir.sh) in a private copy of src/ under OUTDIR, and prints the
# path of the resulting tswg.ko to stdout. All build output goes to stderr.
#
# usage: build-for-gokrazy.sh GOKRAZY_KERNEL_PACKAGE_DIR OUTDIR

set -eu

if [ $# -ne 2 ]; then
	echo "usage: $0 GOKRAZY_KERNEL_PACKAGE_DIR OUTDIR" >&2
	exit 2
fi
scripts=$(dirname "$0")
kdir=$("$scripts/gokrazy-kdir.sh" "$1")
exec "$scripts/build.sh" "$kdir" "$2"

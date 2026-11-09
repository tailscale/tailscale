#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# vmtest.sh runs the tswg natlab vmtests, which live in a tailscale.com
# checkout (by default the one this is in; override with $TAILSCALE_DIR)
# under tstest/natlab/vmtest. Extra arguments are passed to "go test".
#
# usage: vmtest.sh [TEST_REGEXP [go test flags...]]

set -eu

top=$(cd "$(dirname "$0")/.." && pwd)
ts=${TAILSCALE_DIR:-$top/../..}
run=${1:-TestTSWG}
[ $# -gt 0 ] && shift

cd "$ts"
TSWG_DIR=$top exec go test ./tstest/natlab/vmtest/ --run-vm-tests \
	-run "$run" -v -timeout=30m "$@"

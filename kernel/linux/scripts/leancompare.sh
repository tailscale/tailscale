#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# leancompare.sh runs tailscale.com's TestLeanCompare (see leanbench.sh) for
# tswg and wireguard-go three ways: UDP round trips (idle and under a TCP
# load), and TCP throughput with 1 and 4 streams, and prints the medians.
# It's for quick A/B checks of a change; logs go to $TSWG_COMPARE_LOGS
# (default /tmp/leancompare).
#
# Environment:
#   TSWG_COMPARE_MODES  data planes to compare (default tswg,wggo)
#   TSWG_COMPARE_RUNS   runs of each (default 4)
#   TAILSCALE_DIR       the tailscale.com checkout (default: the one this is in)
#
# usage: leancompare.sh [go test flags...]

set -eu

top=$(cd "$(dirname "$0")/.." && pwd)
ts=${TAILSCALE_DIR:-$top/../..}
logs=${TSWG_COMPARE_LOGS:-/tmp/leancompare}
mkdir -p "$logs"
export TSWG_LEAN=1 TSWG_DIR="$top"
export TSWG_LEAN_COMPARE="${TSWG_COMPARE_MODES:-tswg,wggo}"
export TSWG_COMPARE_RUNS="${TSWG_COMPARE_RUNS:-4}"
cd "$ts"
for load in rtt tcp1 tcp4; do
	case $load in
	rtt) TSWG_COMPARE_LOAD=rtt TSWG_COMPARE_STREAMS=1 ;;
	tcp1) TSWG_COMPARE_LOAD=tcp TSWG_COMPARE_STREAMS=1 ;;
	tcp4) TSWG_COMPARE_LOAD=tcp TSWG_COMPARE_STREAMS=4 ;;
	esac
	export TSWG_COMPARE_LOAD TSWG_COMPARE_STREAMS
	echo "== $load" >&2
	go test -count=1 ./tstest/tswgbench/ -run 'TestLeanCompare$' -v -timeout=30m "$@" \
		> "$logs/$load.log" 2>&1 || true
	grep -E -e '--- FAIL|median|kernel reported' "$logs/$load.log" | sed 's/^ *compare_test.go:[0-9]*: //'
done

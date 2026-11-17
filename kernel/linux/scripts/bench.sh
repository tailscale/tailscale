#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# bench.sh runs TestTSWGBenchmark, which compares the tswg kernel data
# plane against wireguard-go on a pair of natlab gokrazy VMs, and writes
# the results as JSON to out/bench-<time>.json (or $TSWG_BENCH_OUT).
#
# Environment:
#   TSWG_BENCH_CPUS  virtual CPUs per VM (default 2)
#   TSWG_BENCH_DUR   length of each throughput run (default 10s)
#   TSWG_BENCH_OUT   where to write the JSON results
#
# usage: bench.sh [go test flags...]

set -eu

top=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$top/out"
export TSWG_BENCH=1
export TSWG_BENCH_OUT="${TSWG_BENCH_OUT:-$top/out/bench-$(date -u +%Y%m%dT%H%M%SZ).json}"
echo "writing results to $TSWG_BENCH_OUT" >&2
exec "$top/scripts/vmtest.sh" 'TestTSWGBenchmark$' "$@"

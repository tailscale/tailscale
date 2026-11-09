#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# leanbench.sh runs tailscale.com's lean data plane benchmark
# (tstest/tswgbench's TestLeanBenchmark): wireguard-go, tswg, the kernel's
# WireGuard and no tunnel, between two QEMU VMs on a host bridge with
# vhost-net, over IPv4 and IPv6. It writes the results as JSON to
# out/leanbench-<time>.json (or $TSWG_BENCH_OUT). It needs passwordless
# sudo (for the bridge and taps), /dev/kvm and /dev/vhost-net.
#
# Environment:
#   TSWG_BENCH_CPUS  virtual CPUs (and NIC queues) per VM (default 4)
#   TSWG_BENCH_DUR   length of each throughput run (default 10s)
#   TSWG_BENCH_OUT   where to write the JSON results
#   TAILSCALE_DIR    the tailscale.com checkout (default ~/src/tailscale.com-tswg)
#
# With -smoke, it runs the quick correctness test (TestLeanSmoke) instead.
#
# usage: leanbench.sh [-smoke] [go test flags...]

set -eu

top=$(cd "$(dirname "$0")/.." && pwd)
ts=${TAILSCALE_DIR:-$HOME/src/tailscale.com-tswg}
run='TestLeanBenchmark$'
if [ "${1:-}" = "-smoke" ]; then
	run='TestLeanSmoke$'
	shift
else
	mkdir -p "$top/out"
	export TSWG_LEAN_BENCH=1 TSWG_BENCH_V6=1
	export TSWG_BENCH_OUT="${TSWG_BENCH_OUT:-$top/out/leanbench-$(date -u +%Y%m%dT%H%M%SZ).json}"
	echo "writing results to $TSWG_BENCH_OUT" >&2
fi
cd "$ts"
TSWG_LEAN=1 TSWG_DIR=$top exec go test ./tstest/tswgbench/ -run "$run" -v -timeout=60m "$@"

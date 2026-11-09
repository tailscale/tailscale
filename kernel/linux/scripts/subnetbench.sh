#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# subnetbench.sh runs tailscale.com's TestLeanSubnetRouter (a subnet router
# with many clients and flows; see tstest/tswgbench/subnet_test.go) on the
# EC2 instances from ec2.sh, once for each router CPU count given, and
# prints the medians. Logs go to $TSWG_SUBNET_LOGS (default /tmp/subnetbench).
#
# Environment (see subnet_test.go for more):
#   TSWG_LEAN_SUBNET   router data planes (default plain,tswg,wggo,kernelwg)
#   TSWG_COMPARE_RUNS  runs of each (default 3)
#   TAILSCALE_DIR      the tailscale.com checkout (default: the one this is in)
#
# usage: subnetbench.sh [ROUTER_CPUS...]   (default: all of the router's CPUs)

set -eu

top=$(cd "$(dirname "$0")/.." && pwd)
ts=${TAILSCALE_DIR:-$top/../..}
logs=${TSWG_SUBNET_LOGS:-/tmp/subnetbench}
mkdir -p "$logs"
export TSWG_LEAN=1 TSWG_DIR="$top"
export TSWG_REMOTE="${TSWG_REMOTE:-$HOME/.cache/tslinux/ec2/hosts.json}"
export TSWG_LEAN_SUBNET="${TSWG_LEAN_SUBNET:-plain,tswg,wggo,kernelwg}"
export TSWG_COMPARE_RUNS="${TSWG_COMPARE_RUNS:-3}"
cd "$ts"
[ $# -gt 0 ] || set -- 0
for cpus in "$@"; do
	echo "== router CPUs: $cpus (0 is all)" >&2
	TSWG_SUBNET_ROUTER_CPUS=$cpus go test -count=1 ./tstest/tswgbench/ \
		-run 'TestLeanSubnetRouter$' -v -timeout=60m > "$logs/cpus$cpus.log" 2>&1 || true
	grep -E -e '--- FAIL|router .* CPUs|median|kernel reported' "$logs/cpus$cpus.log" |
		sed 's/^ *[a-z_]*_test.go:[0-9]*: //'
done

#!/usr/bin/env bash
# Test-only harness. Never installs rules in the host namespace.
set -euo pipefail
binary=$(realpath "$1")
cleanup() {
  sudo ip netns del cgnat-host 2>/dev/null || true
  sudo ip netns del cgnat-peer 2>/dev/null || true
}
# Do not delete a namespace that was not created by this invocation.
for name in cgnat-host cgnat-peer; do
  if sudo ip netns list | grep -q "^$name\( \|$\)"; then
    echo "test namespace already exists: $name" >&2
    exit 1
  fi
done
trap cleanup EXIT
for mode in ${2:-iptables nftables}; do
  sudo ip netns add cgnat-host
  sudo ip netns add cgnat-peer
  sudo ip -n cgnat-host link add cghost type veth peer name cgpeer netns cgnat-peer
  sudo ip -n cgnat-host addr add 100.64.50.2/24 dev cghost
  sudo ip -n cgnat-peer addr add 100.64.50.1/24 dev cgpeer
  sudo ip -n cgnat-host link set lo up
  sudo ip -n cgnat-peer link set lo up
  sudo ip -n cgnat-host link set cghost up
  sudo ip -n cgnat-peer link set cgpeer up
  sudo ip netns exec cgnat-host env TS_CGNAT_TEST_FIREWALL="$mode" \
    "$binary" -test.run '^TestCGNATTransportKernel$' -test.count=1 -test.v
  cleanup
done

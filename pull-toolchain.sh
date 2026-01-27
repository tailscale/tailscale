#!/bin/sh
# Retrieve the latest Go toolchain.
# Set TS_GO_NEXT=1 to update go.toolchain.next.rev instead.
#
set -eu
cd "$(dirname "$0")"

if [ "${TS_GO_NEXT:-}" = "1" ]; then
    go_toolchain_branch_file="go.toolchain.next.branch"
    go_toolchain_rev_file="go.toolchain.next.rev"
else
    go_toolchain_branch_file="go.toolchain.branch"
    go_toolchain_rev_file="go.toolchain.rev"
fi

read -r go_branch <"$go_toolchain_branch_file"
upstream=$(git ls-remote https://github.com/tailscale/go "$go_branch" | awk '{print $1}')
current=$(cat "$go_toolchain_rev_file")
if [ "$upstream" != "$current" ]; then
	echo "$upstream" >"$go_toolchain_rev_file"
fi

# Only update go.toolchain.version and go.toolchain.rev.sri for the main toolchain,
# skipping it if TS_GO_NEXT=1. Those two files are only used by Nix, and as of 2026-01-26
# don't yet support TS_GO_NEXT=1 with flake.nix or in our corp CI.
if [ "${TS_GO_NEXT:-}" != "1" ]; then
    ./tool/go version 2>/dev/null | awk '{print $3}' | sed 's/^go//' > go.toolchain.version
    ./update-flake.sh
fi

if [ -n "$(git diff-index --name-only HEAD -- "$go_toolchain_rev_file" go.toolchain.rev.sri go.toolchain.version)" ]; then
    echo "pull-toolchain.sh: changes imported. Use git commit to make them permanent." >&2
fi

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

# When updating the regular (non-next) toolchain, also bump go.toolchain.next.rev
# if it has fallen behind on the same branch. This happens when "next" was tracking
# a release candidate (e.g. Go 1.26.0rc2) and the regular toolchain later gets
# bumped to a newer release (e.g. Go 1.26.2) on the same branch. At that point
# the "next" rev shouldn't still point at the older RC.
if [ "${TS_GO_NEXT:-}" != "1" ]; then
    read -r next_branch <go.toolchain.next.branch
    if [ "$go_branch" = "$next_branch" ]; then
        next_rev=$(cat go.toolchain.next.rev)
        new_rev=$(cat go.toolchain.rev)
        if [ "$next_rev" != "$new_rev" ]; then
            # Fetch only commit objects (no trees/blobs) with limited depth
            # to keep this fast — we just need the commit graph for ancestry check.
            tmpdir="/tmp/tailscale-pull-toolchain-$$"
            if git clone --bare --filter=tree:0 --depth=20000 --single-branch --branch "$go_branch" \
                https://github.com/tailscale/go "$tmpdir" 2>/dev/null; then
                if git -C "$tmpdir" merge-base --is-ancestor "$next_rev" "$new_rev" 2>/dev/null; then
                    echo "$new_rev" >go.toolchain.next.rev
                    echo "pull-toolchain.sh: also bumped go.toolchain.next.rev to match (was behind on same branch)" >&2
                fi
            fi
            rm -rf "$tmpdir"
        fi
    fi
fi

# Only update go.toolchain.version and go.toolchain.rev.sri for the main toolchain,
# skipping it if TS_GO_NEXT=1. Those two files are only used by Nix, and as of 2026-01-26
# don't yet support TS_GO_NEXT=1 with flake.nix or in our corp CI.
if [ "${TS_GO_NEXT:-}" != "1" ]; then
    ./tool/go version 2>/dev/null | awk '{print $3}' | sed 's/^go//' > go.toolchain.version
    ./tool/go mod edit -go "$(cat go.toolchain.version)"
    ./update-flake.sh
fi

if [ -n "$(git diff-index --name-only HEAD -- "$go_toolchain_rev_file" go.toolchain.next.rev go.toolchain.rev.sri go.toolchain.version)" ]; then
    echo "pull-toolchain.sh: changes imported. Use git commit to make them permanent." >&2
fi

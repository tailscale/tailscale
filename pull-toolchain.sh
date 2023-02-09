#!/bin/sh
# Retrieve the latest Go toolchain.
#
set -eu
cd "$(dirname "$0")"

read -r go_branch <go.toolchain.branch
upstream=$(git ls-remote https://github.com/tailscale/go "$go_branch" | awk '{print $1}')
current=$(cat go.toolchain.rev)
if [ "$upstream" != "$current" ]; then
	echo "$upstream" >go.toolchain.rev
fi

if [ -n "$(git diff-index --name-only HEAD -- go.toolchain.rev)" ]; then
    echo "pull-toolchain.sh: changes imported. Use git commit to make them permanent." >&2
fi

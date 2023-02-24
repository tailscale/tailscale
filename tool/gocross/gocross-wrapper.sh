#!/usr/bin/env sh
# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# gocross-wrapper.sh is a wrapper that can be aliased to 'go', which
# transparently builds gocross using a "bootstrap" Go toolchain, and
# then invokes gocross.

set -eu

if [ "${CI:-}" = "true" ]; then
    set -x
fi

# Locate a bootstrap toolchain and (re)build gocross if necessary. We run all of
# this in a subshell because posix shell semantics make it very easy to
# accidentally mutate the input environment that will get passed to gocross at
# the bottom of this script.
(
repo_root="$(dirname $0)/../.."

toolchain="$HOME/.cache/tailscale-go"

if [ ! -d "$toolchain" ]; then
    mkdir -p "$HOME/.cache"

    # We need any Go toolchain to build gocross, but the toolchain also has to
    # be reasonably recent because we upgrade eagerly and gocross might not
    # build with Go N-1. So, if we have no cached tailscale toolchain at all,
    # fetch the initial one in shell. Once gocross is built, it'll manage
    # updates.
    read -r REV <$repo_root/go.toolchain.rev

    case "$REV" in
    /*)
        toolchain="$REV"
        ;;
    *)
        # This works for linux and darwin, which is sufficient
        # (we do not build tailscale-go for other targets).
        HOST_OS=$(uname -s | tr A-Z a-z)
        HOST_ARCH="$(uname -m)"
        if [ "$HOST_ARCH" = "aarch64" ]; then
            # Go uses the name "arm64".
            HOST_ARCH="arm64"
        elif [ "$HOST_ARCH" = "x86_64" ]; then
            # Go uses the name "amd64".
            HOST_ARCH="amd64"
        fi

        rm -rf "$toolchain" "$toolchain.extracted"
        curl -f -L -o "$toolchain.tar.gz" "https://github.com/tailscale/go/releases/download/build-${REV}/${HOST_OS}-${HOST_ARCH}.tar.gz"
        mkdir -p "$toolchain"
        (cd "$toolchain" && tar --strip-components=1 -xf "$toolchain.tar.gz")
        echo "$REV" >"$toolchain.extracted"
        ;;
    esac
fi

# Binaries run with `gocross run` can reinvoke gocross, resulting in a
# potentially fancy build that invokes external linkers, might be
# cross-building for other targets, and so forth. In one hilarious
# case, cmd/cloner invokes go with GO111MODULE=off at some stage.
#
# Anyway, build gocross in a stripped down universe.
gocross_path="$repo_root/gocross"
gocross_ok=0
if [ -x "$gocross_path" ]; then
	gotver="$($gocross_path gocross-version 2>/dev/null || echo '')"
	wantver="$(git rev-parse HEAD)"
	if [ "$gotver" = "$wantver" ]; then
		gocross_ok=1
	fi
fi
if [ "$gocross_ok" = "0" ]; then
    unset GOOS
    unset GOARCH
    unset GO111MODULE
    unset GOROOT
    export CGO_ENABLED=0
    "$toolchain/bin/go" build -o "$gocross_path" -ldflags='-X tailscale.com/version/gitCommitStamp=$wantver' tailscale.com/tool/gocross
fi
) # End of the subshell execution.

exec "$(dirname $0)/../../gocross" "$@"

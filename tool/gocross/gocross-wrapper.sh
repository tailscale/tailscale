#!/usr/bin/env bash
# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# gocross-wrapper.sh is a wrapper that can be aliased to 'go', which
# transparently builds gocross using a "bootstrap" Go toolchain, and
# then invokes gocross.

set -euo pipefail

if [[ "${CI:-}" == "true" && "${NOBASHDEBUG:-}" != "true" ]]; then
    set -x
fi

# Locate a bootstrap toolchain and (re)build gocross if necessary. We run all of
# this in a subshell because posix shell semantics make it very easy to
# accidentally mutate the input environment that will get passed to gocross at
# the bottom of this script.
(
repo_root="${BASH_SOURCE%/*}/../.."

# Figuring out if gocross needs a rebuild, as well as the rebuild itself, need
# to happen with CWD inside this repo. Since we're in a subshell entirely
# dedicated to wrangling gocross and toolchains, cd over now before doing
# anything further so that the rest of this logic works the same if gocross is
# being invoked from somewhere else.
cd "$repo_root"

# toolchain, set below, is the root of the Go toolchain we'll use to build
# gocross.
#
# It's set to either an explicit Go toolchain directory (if go.toolchain.rev has
# a value with a leading slash, for testing new toolchains), or otherwise in the
# common case it'll be "$HOME/.cache/tsgo/GITHASH" where GITHASH is the contents
# of the go.toolchain.rev file and the git commit of the
# https://github.com/tailscale/go release artifact to download.
toolchain=""

read -r REV <go.toolchain.rev
case "$REV" in
/*)
    toolchain="$REV"
    ;;
*)
    toolchain="$HOME/.cache/tsgo/$REV"
    if [[ ! -f "$toolchain.extracted" ]]; then
        mkdir -p "$HOME/.cache/tsgo"
        rm -rf "$toolchain" "$toolchain.extracted"

        echo "# Downloading Go toolchain $REV" >&2

        # This works for linux and darwin, which is sufficient
        # (we do not build tailscale-go for other targets).
        HOST_OS=$(uname -s | tr A-Z a-z)
        HOST_ARCH="$(uname -m)"
        if [[ "$HOST_ARCH" == "aarch64" ]]; then
            # Go uses the name "arm64".
            HOST_ARCH="arm64"
        elif [[ "$HOST_ARCH" == "x86_64" ]]; then
            # Go uses the name "amd64".
            HOST_ARCH="amd64"
        fi
        curl -f -L -o "$toolchain.tar.gz" "https://github.com/tailscale/go/releases/download/build-${REV}/${HOST_OS}-${HOST_ARCH}.tar.gz"
        mkdir -p "$toolchain"
        (cd "$toolchain" && tar --strip-components=1 -xf "$toolchain.tar.gz")
        echo "$REV" >"$toolchain.extracted"
        rm -f "$toolchain.tar.gz"

        # Do some cleanup of old toolchains while we're here.
        for hash in $(find "$HOME/.cache/tsgo" -maxdepth 1 -type f -name '*.extracted' -mtime 90 -exec basename {} \; | sed 's/.extracted$//'); do
            echo "# Cleaning up old Go toolchain $hash" >&2
            rm -rf "$HOME/.cache/tsgo/$hash"
            rm -rf "$HOME/.cache/tsgo/$hash.extracted"
        done
    fi
    ;;
esac

if [[ -d "$toolchain" ]]; then
    # A toolchain exists, but is it recent enough to compile gocross? If not,
    # wipe it out so that the next if block fetches a usable one.
    want_go_minor="$(grep -E '^go ' "go.mod" | cut -f2 -d'.')"
    have_go_minor=""
    if [[ -f "$toolchain/VERSION" ]]; then
        have_go_minor="$(head -1 "$toolchain/VERSION" | cut -f2 -d'.')"
    fi
    # Shortly before stable releases, we run release candidate
    # toolchains, which have a non-numeric suffix on the version
    # number. Remove the rc qualifier, we just care about the minor
    # version.
    have_go_minor="${have_go_minor%rc*}"
    if [[ -z "$have_go_minor" || "$have_go_minor" -lt "$want_go_minor" ]]; then
        rm -rf "$toolchain" "$toolchain.extracted"
    fi
fi

# Binaries run with `gocross run` can reinvoke gocross, resulting in a
# potentially fancy build that invokes external linkers, might be
# cross-building for other targets, and so forth. In one hilarious
# case, cmd/cloner invokes go with GO111MODULE=off at some stage.
#
# Anyway, build gocross in a stripped down universe.
gocross_path="./gocross"
gocross_ok=0
wantver="$(git rev-parse HEAD)"
if [[ -x "$gocross_path" ]]; then
	gotver="$($gocross_path gocross-version 2>/dev/null || echo '')"
	if [[ "$gotver" == "$wantver" ]]; then
		gocross_ok=1
	fi
fi
if [[ "$gocross_ok" == "0" ]]; then
    unset GOOS
    unset GOARCH
    unset GO111MODULE
    unset GOROOT
    export CGO_ENABLED=0
    "$toolchain/bin/go" build -o "$gocross_path" -ldflags "-X tailscale.com/version.gitCommitStamp=$wantver" tailscale.com/tool/gocross
fi
) # End of the subshell execution.

exec "${BASH_SOURCE%/*}/../../gocross" "$@"

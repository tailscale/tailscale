#!/usr/bin/env sh

#
# Runs `go build` with flags configured for docker distribution. All
# it does differently from `go build` is burn git commit and version
# information into the binaries inside docker, so that we can track down user
# issues.
#
############################################################################
#
# WARNING: Tailscale is not yet officially supported in Docker,
# Kubernetes, etc.
#
# It might work, but we don't regularly test it, and it's not as polished as
# our currently supported platforms. This is provided for people who know
# how Tailscale works and what they're doing.
#
# Our tracking bug for officially support container use cases is:
#    https://github.com/tailscale/tailscale/issues/504
#
# Also, see the various bugs tagged "containers":
#    https://github.com/tailscale/tailscale/labels/containers
#
############################################################################

set -eu

eval $(./version/version.sh)

GOFLAGS='-tags xversion -ldflags '"-X tailscale.com/version.Long=${VERSION_LONG} -X tailscale.com/version.Short=${VERSION_SHORT} -X tailscale.com/version.GitCommit=${VERSION_GIT_HASH}"
docker build --build-arg goflags_arg="'""${GOFLAGS}""'" -t tailscale:tailscale .

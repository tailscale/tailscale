#!/usr/bin/env sh

#
# Runs `go build` with flags configured for docker distribution. All
# it does differently from `go build` is burn git commit and version
# information into the binaries inside docker, so that we can track down user
# issues.
#
############################################################################
#
# WARNING: Tailscale is not yet officially supported in container
# environments, such as Docker and Kubernetes. Though it should work, we
# don't regularly test it, and we know there are some feature limitations.
#
# See current bugs tagged "containers":
#    https://github.com/tailscale/tailscale/labels/containers
#
############################################################################

set -eu

eval $(./build_dist.sh shellvars)

go run github.com/tailscale/mkctr@latest \
  --base="ghcr.io/tailscale/alpine-base:3.14" \
  --gopaths="\
    tailscale.com/cmd/tailscale:/usr/local/bin/tailscale, \
    tailscale.com/cmd/tailscaled:/usr/local/bin/tailscaled" \
  --ldflags="\
    -X tailscale.com/version.Long=${VERSION_LONG} \
    -X tailscale.com/version.Short=${VERSION_SHORT} \
    -X tailscale.com/version.GitCommit=${VERSION_GIT_HASH}" \
  --tags="${VERSION_SHORT},${VERSION_MINOR}" \
  --repos="tailscale/tailscale,ghcr.io/tailscale/tailscale" \
  --push

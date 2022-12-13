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

# Use the "go" binary from the "tool" directory (which is github.com/tailscale/go)
export PATH=$PWD/tool:$PATH

eval $(./build_dist.sh shellvars)
DEFAULT_TAGS="v${VERSION_SHORT},v${VERSION_MINOR}"
DEFAULT_REPOS="tailscale/tailscale,ghcr.io/tailscale/tailscale"
DEFAULT_BASE="ghcr.io/tailscale/alpine-base:3.16"
DEFAULT_TARGET="client"

PUSH="${PUSH:-false}"
REPOS="${REPOS:-${DEFAULT_REPOS}}"
TAGS="${TAGS:-${DEFAULT_TAGS}}"
BASE="${BASE:-${DEFAULT_BASE}}"
TARGET="${TARGET:-${DEFAULT_TARGET}}"

case "$TARGET" in
  client)
    go run github.com/tailscale/mkctr \
      --gopaths="\
        tailscale.com/cmd/tailscale:/usr/local/bin/tailscale, \
        tailscale.com/cmd/tailscaled:/usr/local/bin/tailscaled, \
        tailscale.com/cmd/containerboot:/usr/local/bin/containerboot" \
      --ldflags="\
        -X tailscale.com/version.Long=${VERSION_LONG} \
        -X tailscale.com/version.Short=${VERSION_SHORT} \
        -X tailscale.com/version.GitCommit=${VERSION_GIT_HASH}" \
      --base="${BASE}" \
      --tags="${TAGS}" \
      --repos="${REPOS}" \
      --push="${PUSH}" \
      /usr/local/bin/containerboot
    ;;
  operator)
    go run github.com/tailscale/mkctr \
      --gopaths="tailscale.com/cmd/k8s-operator:/usr/local/bin/operator" \
      --ldflags="\
        -X tailscale.com/version.Long=${VERSION_LONG} \
        -X tailscale.com/version.Short=${VERSION_SHORT} \
        -X tailscale.com/version.GitCommit=${VERSION_GIT_HASH}" \
      --base="${BASE}" \
      --tags="${TAGS}" \
      --repos="${REPOS}" \
      --push="${PUSH}" \
      /usr/local/bin/operator
    ;;
  *)
    echo "unknown target: $TARGET"
    exit 1
    ;;
esac
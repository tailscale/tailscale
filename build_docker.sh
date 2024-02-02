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
export PATH="$PWD"/tool:"$PATH"

eval "$(./build_dist.sh shellvars)"

DEFAULT_TARGET="client"
DEFAULT_TAGS="v${VERSION_SHORT},v${VERSION_MINOR}"
DEFAULT_BASE="tailscale/alpine-base:3.18"

PUSH="${PUSH:-false}"
TARGET="${TARGET:-${DEFAULT_TARGET}}"
TAGS="${TAGS:-${DEFAULT_TAGS}}"
BASE="${BASE:-${DEFAULT_BASE}}"
PLATFORM="${PLATFORM:-}" # default to all platforms

case "$TARGET" in
  client)
    DEFAULT_REPOS="tailscale/tailscale"
    REPOS="${REPOS:-${DEFAULT_REPOS}}"
    go run github.com/tailscale/mkctr \
      --gopaths="\
        tailscale.com/cmd/tailscale:/usr/local/bin/tailscale, \
        tailscale.com/cmd/tailscaled:/usr/local/bin/tailscaled, \
        tailscale.com/cmd/containerboot:/usr/local/bin/containerboot" \
      --ldflags="\
        -X tailscale.com/version.longStamp=${VERSION_LONG} \
        -X tailscale.com/version.shortStamp=${VERSION_SHORT} \
        -X tailscale.com/version.gitCommitStamp=${VERSION_GIT_HASH}" \
      --base="${BASE}" \
      --tags="${TAGS}" \
      --gotags="ts_kube" \
      --repos="${REPOS}" \
      --push="${PUSH}" \
      --target="${PLATFORM}" \
      /usr/local/bin/containerboot
    ;;
  operator)
    DEFAULT_REPOS="tailscale/k8s-operator"
    REPOS="${REPOS:-${DEFAULT_REPOS}}"
    go run github.com/tailscale/mkctr \
      --gopaths="tailscale.com/cmd/k8s-operator:/usr/local/bin/operator" \
      --ldflags="\
        -X tailscale.com/version.longStamp=${VERSION_LONG} \
        -X tailscale.com/version.shortStamp=${VERSION_SHORT} \
        -X tailscale.com/version.gitCommitStamp=${VERSION_GIT_HASH}" \
      --base="${BASE}" \
      --tags="${TAGS}" \
      --repos="${REPOS}" \
      --push="${PUSH}" \
      --target="${PLATFORM}" \
      /usr/local/bin/operator
    ;;
  k8s-nameserver)
    DEFAULT_REPOS="tailscale/k8s-nameserver"
    REPOS="${REPOS:-${DEFAULT_REPOS}}"
    go run github.com/tailscale/mkctr \
      --gopaths="tailscale.com/cmd/k8s-nameserver:/usr/local/bin/k8s-nameserver" \
      --ldflags=" \
        -X tailscale.com/version.longStamp=${VERSION_LONG} \
        -X tailscale.com/version.shortStamp=${VERSION_SHORT} \
        -X tailscale.com/version.gitCommitStamp=${VERSION_GIT_HASH}" \
      --base="${BASE}" \
      --tags="${TAGS}" \
      --repos="${REPOS}" \
      --push="${PUSH}" \
      --target="${PLATFORM}" \
      /usr/local/bin/k8s-nameserver
    ;;
  *)
    echo "unknown target: $TARGET"
    exit 1
    ;;
esac

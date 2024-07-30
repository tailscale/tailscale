#!/usr/bin/env sh
#
# This script builds Tailscale container images using
# github.com/tailscale/mkctr.
# By default the images will be tagged with the current version and git
# hash of this repository as produced by ./cmd/mkversion.
# This is the image build mechanim used to build the official Tailscale
# container images.

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
      --gotags="ts_kube,ts_package_container" \
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

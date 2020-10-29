#!/usr/bin/env sh
#
# Runs `go build` with flags configured for binary distribution. All
# it does differently from `go build` is burn git commit and version
# information into the binaries, so that we can track down user
# issues.
#
# If you're packaging Tailscale for a distro, please consider using
# this script, or executing equivalent commands in your
# distro-specific build system.

set -euo pipefail

describe=$(./version/describe.sh)
commit=$(git rev-parse --verify --quiet HEAD)

long=$(./version/mkversion.sh long "$describe" "")
short=$(./version/mkversion.sh short "$describe" "")

exec go build -tags xversion -ldflags "-X tailscale.com/version.Long=${long} -X tailscale.com/version.Short=${short} -X tailscale.com/version.GitCommit=${commit}" "$@"

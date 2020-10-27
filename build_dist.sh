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

describe=$(git describe --long --abbrev=9)
commit=$(git describe --dirty --exclude "*" --always --abbrev=200)

long=$(./version/mkversion.sh long "$describe")
short=$(./version/mkversion.sh short "$describe")

exec go build -tags xversion -ldflags "-X tailscale.com/version.LONG=${long} -X tailscale.com/version.SHORT=${short} -X tailscale.com/version.GitRevision=${commit}" "$@"

#!/usr/bin/env sh
set -eu

# only for Tailscale brew maintainer, to local-only serve a source tarball standin, during brew testing

eval $(brew/vars.sh)

python3 -m http.server --directory brew/local/tarball-serve-root --bind localhost $TS_TARBALL_PORT

# why the above? during one formula/release test brew may expect to fetch a tarball from (w/version varying):
#     http://localhost:$TS_TARBALL_PORT/tailscale/tailscale/archive/v$TS_VER.tar.gz
# where $TS_VER is like 1.5.0
# therefore under tarball-serve-root/ that file should be in:
#     tailscale/tailscale/archive/

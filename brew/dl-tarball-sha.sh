#!/usr/bin/env sh
set -eu

eval $(brew/vars.sh)

#URLBASE=https://github.com
URLBASE=http://localhost
TARBALL=v$TS_VER.tar.gz
curl -OL $URLBASE/tailscale/tailscale/archive/$TARBALL
shasum -a256 ./$TARBALL # TODO(mkramlich): not the proper point in lifecycle to calc this

#!/usr/bin/env sh
set -eu

# does not create an official release source tarball per GitHub. creates a standin for it, for brew test purposes only

eval $(tailscale/brew/vars.sh) # TODO(mkramlich): doc the path deviance or automate away

TARBALL_ARCHIVE=tailscale/brew/local/tarball-serve-root/tailscale/tailscale/archive

mkdir -p $TARBALL_ARCHIVE

TARBALL=$TARBALL_ARCHIVE/v$TS_VER.tar.gz

# assume a repo is cloned at that dir tree location, and its file state is what we want
echo making $TARBALL
tar -czf $TARBALL tailscale-$TS_VER/.gitignore tailscale-$TS_VER/.github/* tailscale-$TS_VER/.gitattributes tailscale-$TS_VER/*
shasum -a256 ./$TARBALL

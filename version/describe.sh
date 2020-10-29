#!/bin/sh
#
# Constructs a "git describe" compatible version number by using the
# information in the VERSION file, rather than git tags.

set -eu

dir="$(dirname $0)"
verfile="$dir/../VERSION"

read -r version hash <"$verfile"

if [ -z "$hash" ]; then
    # If no explicit hash was given, use the last time the version
    # file changed as the "origin" hash for this version.
    hash="$(git rev-list --max-count=1 HEAD -- $verfile)"
fi

if [ -z "$hash" ]; then
    echo "Couldn't find base git hash for version '$version'" >2
    exit 1
fi

head="$(git rev-parse --short=9 HEAD)"
changecount="$(git rev-list ${hash}..HEAD | wc -l)"
echo "v${version}-${changecount}-g${head}"

#!/bin/sh

set -eu

mode=$1
describe=$2
other=$3

# Git describe output overall looks like
# MAJOR.MINOR.PATCH-NUMCOMMITS-GITHASH. Depending on the tag being
# described and the state of the repo, ver can be missing PATCH,
# NUMCOMMITS, or both.
#
# Valid values look like: 1.2.3-1234-abcdef, 0.98-1234-abcdef,
# 1.0.0-abcdef, 0.99-abcdef.
ver="${describe#v}"
stem="${ver%%-*}" # Just the semver-ish bit e.g. 1.2.3, 0.98
suffix="${ver#$stem}" # The rest e.g. -23-abcdef, -abcdef

# Normalize the stem into a full major.minor.patch semver. We might
# not use all those pieces depending on what kind of version we're
# making, but it's good to have them all on hand.
case "$stem" in
    *.*.*)
        # Full SemVer, nothing to do
        stem="$stem"
        ;;
    *.*)
        # Old style major.minor, add a .0
        stem="${stem}.0"
        ;;
    *)
        echo "Unparseable version $stem" >&2
        exit 1
        ;;
esac
major=$(echo "$stem" | cut -f1 -d.)
minor=$(echo "$stem" | cut -f2 -d.)
patch=$(echo "$stem" | cut -f3 -d.)

# Extract the change count and git ID from the suffix.
case "$suffix" in
    -*-*)
        # Has both a change count and a commit hash.
        changecount=$(echo "$suffix" | cut -f2 -d-)
        githash=$(echo "$suffix" | cut -f3 -d-)
        ;;
    -*)
        # Git hash only, change count is zero.
        changecount="0"
        githash=$(echo "$suffix" | cut -f2 -d-)
        ;;
    *)
        echo "Unparseable version suffix $suffix" >&2
        exit 1
        ;;
esac

# The git hash is of the form "gCOMMITHASH". We want to replace the
# 'g' with a 't', for "tailscale", to convey that it's specifically
# the commit hash of the tailscale repo.
if [ -n "$githash" ]; then
    # POSIX shell doesn't understand ${foo:1:9} syntax, gaaah.
    githash="$(echo $githash | cut -c2-10)"
    githash="t${githash}"
fi

# "other" is a second git commit hash for another repository used to
# build the Tailscale code. In practice it's either the commit hash in
# the Android repository, or the commit hash of Tailscale's
# proprietary repository (which pins a bunch things like build scripts
# used and Go toolchain version).
if [ -n "$other" ]; then
    other="$(echo $other | cut -c1-9)"
    other="-g${other}"
fi

# Validate that the version data makes sense. Rules:
#  - Odd number minors are unstable. Patch must be 0, and gets
#    replaced by changecount.
#  - Even number minors are stable. Changecount must be 0, and
#    gets removed.
#
# After this section, we only use major/minor/patch, which have been
# tweaked as needed.
if expr "$minor" : "[0-9]*[13579]$" >/dev/null; then
    # Unstable
    if [ "$patch" != "0" ]; then
        # This is a fatal error, because a non-zero patch number
        # indicates that we created an unstable git tag in violation
        # of our versioning policy, and we want to blow up loudly to
        # get that fixed.
        echo "Unstable release $describe has a non-zero patch number, which is not allowed" >&2
        exit 1
    fi
    patch="$changecount"
else
    # Stable
    if [ "$changecount" != "0" ]; then
        # This is a commit that's sitting between two stable
        # releases. We never want to release such a commit to the
        # pbulic, but it's useful to be able to build it for
        # debugging. Just force the version to 0.0.0, so that we're
        # forced to rely on the git commit hash.
        major="0"
        minor="0"
        patch="0"
    fi
fi

if [ "$minor" -eq 1 ]; then
    # Hack for 1.1: add 1000 to the patch number, so that builds that
    # use the OSS change count order after the builds that used the
    # proprietary repo's changecount. Otherwise, the version numbers
    # would go backwards and things would be unhappy.
    patch=$((patch + 1000))
fi

case "$1" in
    long)
        echo "${major}.${minor}.${patch}-${githash}${other}"
        ;;
    short)
        echo "${major}.${minor}.${patch}"
        ;;
    xcode)
        # CFBundleShortVersionString: the "short name" used in the App
        # Store.  eg. 0.92.98
        echo "VERSION_NAME = ${major}.${minor}.${patch}"
        # CFBundleVersion: the build number. Needs to be 3 numeric
        # sections that increment for each release according to SemVer
        # rules.
        #
        # We start counting at 100 because we submitted using raw
        # build numbers before, and Apple doesn't let you start over.
        # e.g. 0.98.3 -> 100.98.3
        echo "VERSION_ID = $((major + 100)).${minor}.${patch}"        
        ;;
esac

#!/bin/sh

set -eu

mode=$1
describe=$2

ver="${describe#v}"
stem="${ver%%-*}" # e.g. 1.2.3
suffix="${ver#$stem}" # e.g. -0-abcdefghi

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

# Validate that the version data makes sense. Rules:
#  - Odd number minors are unstable. Patch must be 0, and gets
#    replaced by changecount.
#  - Even number minors are stable. Changecount must be 0, and
#    gets removed.
#
# After this section, we only use major/minor/patch, which have been
# tweaked as needed.
if expr "$minor" : "[13579][13579]*$" >/dev/null; then
    # Unstable
    if [ "$patch" != "0" ]; then
        echo "Unstable release $describe has a non-zero patch number, which is not allowed" >&2
        exit 1
    fi
    patch="$changecount"
else
    # Stable
    if [ "$changecount" != "0" ]; then
        echo "Stable release $describe has non-zero change count, which is not allowed" >&2
        exit 1
    fi
fi

case "$1" in
    long)
        echo "${major}.${minor}.${patch}-${githash}"
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

#!/bin/sh

set -eu

mode=$1
describe=$2

long() {
    ver="${describe#v}"
    stem="${ver%%-*}"
    case "$stem" in
        *.*.*)
            # Full SemVer, nothing to do.
            semver="${stem}"
        ;;
        *.*)
            # Old style major.minor, add a .0
            semver="${stem}.0"
            ;;
        *)
            echo "Unparseable version $stem" >&2
            exit 1
            ;;
    esac
    suffix="${ver#$stem}"
    case "$suffix" in
        -*-*)
            # Has a change count in addition to the commit hash.
        ;;
        -*)
            # Missing change count, add one.
            suffix="-0${suffix}"
            ;;
        *)
            echo "Unexpected version suffix" >&2
            exit 1
    esac
    echo "${semver}${suffix}"
}

short() {
    ver="$(long)"
    case "$ver" in
        *-*-*)
            echo "${ver%-*}"
            ;;
        *-*)
            echo "$ver"
            ;;
        *)
            echo "Long version in invalid format" >&2
            exit 1
            ;;
    esac
}

xcode() {
    ver=$(short | sed -e 's/-/./')
    major=$(echo "$ver" | cut -f1 -d.)
    minor=$(echo "$ver" | cut -f2 -d.)
    patch=$(echo "$ver" | cut -f3 -d.)
    changecount=$(echo "$ver" | cut -f4 -d.)

    # name should be like git-describe, but without the git suffix or
    # the leading v. For example, for git-describe of
    # "v0.100.0-15-gce1b52bb7" we want:
    #
    #   VERSION_NAME = 0.100.0-15
    #   VERSION_ID = 100.100.15
    name=$(echo "$describe" | sed -e 's/^v//' | sed -e 's/-g.*//' | sed -e 's/-0$//')

    # Apple version numbers must be major.minor.patch. We have 4 fields
    # because we need major.minor.patch for go module compatibility, and
    # changecount for automatic version numbering of unstable builds. To
    # resolve this, for Apple builds, we combine changecount into patch:
    patch=$((patch*10000 + changecount))

    # CFBundleShortVersionString: the "short name" used in the App Store.
    # e.g. 0.92.98
    echo "VERSION_NAME = $name"
    # CFBundleVersion: the build number. Needs to be 3 numeric sections
    # that increment for each release according to SemVer rules.
    #
    # We start counting at 100 because we submitted using raw build
    # numbers before, and Apple doesn't let you start over.
    # e.g. 0.98.3-123 -> 100.98.3123
    major=$((major + 100))
    echo "VERSION_ID = $major.$minor.$patch"
}

case "$mode" in
    long)
        long
    ;;
    short)
        short
    ;;
    xcode)
        xcode
    ;;
esac

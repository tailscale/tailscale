#!/bin/bash

set -eu

# Clean up folders and files created during build.
function cleanup() {
    rm -rf /Tailscale/$ARCH
    rm -f /Tailscale/sed*
    rm -f /Tailscale/qpkg.cfg

    # If this build was signed, a .qpkg.codesigning file will be created as an
    # artifact of the build
    # (see https://github.com/qnap-dev/qdk2/blob/93ac75c76941b90ee668557f7ce01e4b23881054/QDK_2.x/bin/qbuild#L992).
    #
    # go/client-release doesn't seem to need these, so we delete them here to
    # avoid uploading them to pkgs.tailscale.com.
    rm -f /out/*.qpkg.codesigning
}
trap cleanup EXIT

mkdir -p /Tailscale/$ARCH
cp /tailscaled /Tailscale/$ARCH/tailscaled
cp /tailscale /Tailscale/$ARCH/tailscale

sed "s/\$QPKG_VER/$TSTAG-$QNAPTAG/g" /Tailscale/qpkg.cfg.in > /Tailscale/qpkg.cfg

qbuild --root /Tailscale --build-arch $ARCH --build-dir /out

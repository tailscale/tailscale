#!/bin/bash

set -eu

# Clean up folders and files created during build.
function cleanup() {
    rm -rf /Tailscale/$ARCH
    rm -f /Tailscale/sed*
    rm -f /Tailscale/qpkg.cfg
}
trap cleanup EXIT

mkdir -p /Tailscale/$ARCH
cp /tailscaled /Tailscale/$ARCH/tailscaled
cp /tailscale /Tailscale/$ARCH/tailscale

sed "s/\$QPKG_VER/$TSTAG-$QNAPTAG/g" /Tailscale/qpkg.cfg.in > /Tailscale/qpkg.cfg

qbuild --root /Tailscale --build-arch $ARCH --build-dir /out

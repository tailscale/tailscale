#!/bin/bash

set -eu

sed "s/\$QPKG_VER/0.0.001/g" /Tailscale/qpkg.cfg.in > /qpkg.cfg

echo "Running qbuild"
qbuild --verify-code-signing /in/$1

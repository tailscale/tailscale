#!/usr/bin/env sh
set -eu

eval $(brew/vars.sh)

sudo $TS_BIN/tailscale -socket=$TS_SOCK up

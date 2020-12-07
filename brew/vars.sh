#!/usr/bin/env sh
set -eu

# TODO(mkramlich): elim redundancy with or otherwise maybe take advantage of version/version.sh

BREW=`brew --prefix` # because varies; /usr/local on Intel, /opt/homebrew on ARM64/M1/AppleSilicon

# TODO(mkramlich): Cellar

cat <<EOF
TS_VER=1.5.0
TS_COMMIT_PIN=188bb142691c8b97673a9cb2aebd9f1521e9bb12
TS_BIN=$BREW/bin
TS_SOCK=$BREW/var/run/tailscale/tailscaled.sock
TS_STATE=$BREW/var/lib/tailscale/tailscaled.state
TS_LOG_DIR=$BREW/var/log/tailscale
TS_CELLAR=$BREW/Cellar/tailscale
TS_PLIST=homebrew.mxcl.tailscale.plist
TS_TARBALL_PORT=8901
TS_FORMULA=brew/tailscale.rb
BREW=$BREW
INSTALLED_PLIST_DIR=/Library/LaunchDaemons
EOF

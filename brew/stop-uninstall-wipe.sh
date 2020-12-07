#!/usr/bin/env sh
set -u # also -e?

eval $(brew/vars.sh)

echo
echo SUDO is $SUDO

echo
echo stopping...
$SUDO brew services stop tailscale
$SUDO brew services list | grep tailscale
ps -ef | grep tailscaled | grep -v "grep tailscaled" # TODO(mkramlich): do better
# TODO(mkramlich): the installed plist is gone?

echo
echo uninstalling...
brew uninstall --force tailscale
$SUDO brew services list | grep tailscale

echo
echo deleting...
$SUDO rm -rf $TS_CELLAR/$TS_VER
$SUDO rm -f $BREW/var/lib/tailscale/*
$SUDO rm -f $TS_LOG_DIR/*
rmdir $BREW/var/lib/tailscale
rmdir $TS_LOG_DIR
rmdir $BREW/var/run/tailscale
rm $BREW/opt/tailscale  # was symlink to $TS_CELLAR/$TS_VER
rmdir $TS_CELLAR
find $BREW | grep -i tailscale
find /opt | grep -i tailscale
# TODO(mkramlich): wipeout brew git checkout cache and/or add test for with-vs-without

#!/usr/bin/env sh
set -eu

# TODO(mkramlich):
#   dl-tarball-sha.sh
#   make-test-source-tarball.sh


echo test variant: global, tb-local
#TODO(mkramlich): for the tb-local tests, server-tarball.sh should be running, with tarball in place
cp brew/tailscale{.tb-local,}.rb
# brew services (via launchd) start as a global boot daemon (in /Library/LaunchDaemons), running as root
# TODO(mkramlich): confirm at reboot starts & works
SUDO="sudo" INSTALLED_PLIST_DIR=/Library/LaunchDaemons brew/install-start-with-checks.sh
SUDO="sudo" INSTALLED_PLIST_DIR=/Library/LaunchDaemons brew/stop-uninstall-wipe.sh


echo test variant: global, tb-github
cp brew/tailscale{.tb-github,}.rb
# brew services (via launchd) start as a global boot daemon (in /Library/LaunchDaemons), running as root
# TODO(mkramlich): confirm at reboot starts & works
SUDO="sudo" INSTALLED_PLIST_DIR=/Library/LaunchDaemons brew/install-start-with-checks.sh
SUDO="sudo" INSTALLED_PLIST_DIR=/Library/LaunchDaemons brew/stop-uninstall-wipe.sh


echo test variant: global, commit-pin
cp brew/tailscale{.commit-pin,}.rb
# brew services (via launchd) start as a global boot daemon (in /Library/LaunchDaemons), running as root
# TODO(mkramlich): confirm at reboot starts & works
SUDO="sudo" INSTALLED_PLIST_DIR=/Library/LaunchDaemons brew/install-start-with-checks.sh
SUDO="sudo" INSTALLED_PLIST_DIR=/Library/LaunchDaemons brew/stop-uninstall-wipe.sh


#####################################

# brew services (via launchd) start as a user login agent (in ~/Library/LaunchAgents), BUT runs as sudo
# TODO(mkramlich): just a WIP POC, much lower priority than boot perm, might drop
#SUDO="" INSTALLED_PLIST_DIR=~/Library/LaunchAgents brew/install-start-with-checks.sh
#SUDO="" INSTALLED_PLIST_DIR=~/Library/LaunchAgents brew/stop-uninstall-wipe.sh

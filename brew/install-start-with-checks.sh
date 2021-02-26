#!/usr/bin/env sh
set -eu

eval $(brew/vars.sh)

echo
echo SUDO is $SUDO

echo
echo versions...
brew --version
brew config
go version
echo maintainer VERSION.txt: `cat VERSION.TXT`
echo maintainer script version/version.sh exec:
version/version.sh # we don't truly use this (yet?), just print here as helpful info for later analysis
# TODO(mkramlich) make distinction clear between maintainer script source ver and target package vers

echo
echo brew doctor...
set +e # to turn -e off (relax this only for time being)
brew doctor # TODO(mkramlich): for brew maintainer, best if have no findings and exit 0
set -e # to turn back on

echo
echo audit formula...
# requires Internet access for some audit checks:
brew audit --strict --online --formula $TS_FORMULA # keep this run exit 0 (NOTE: Homebrew can be noisy if updates)

echo
echo installing...
#brew install -v --build-from-source $TS_FORMULA
brew install -v --formula $TS_FORMULA

echo
echo checking exe location and diffs...
diff $TS_BIN/tailscale $TS_CELLAR/$TS_VER/bin/tailscale # TODO(mkramlich): FIXME in test case global,tb-github; want 1.5.0, got 1.4.4, SHOULD want 1.4.4 cuz 1.4.4 correct
diff $TS_BIN/tailscaled $TS_CELLAR/$TS_VER/bin/tailscaled

echo
echo check if brew has formula...
brew list tailscale

echo
echo check if installed formula matches orig...
diff $TS_FORMULA $TS_CELLAR/$TS_VER/.$TS_FORMULA

echo
echo lint of the generated launchctl plist for homebrew tailscale...
# should print "<filepath>: OK" and exit 0; brew services (or launchctl) below
# might reject (or silently allow) any given !0 case so better to catch an issue
# early/wider than not, and automate extra clues for maintainer
plutil -lint $TS_CELLAR/$TS_VER/$TS_PLIST

echo
echo brew test before starting...
brew test $TS_FORMULA

echo
echo starting...
$SUDO brew services start tailscale

echo
echo pausing as tailscaled starts...
sleep 8

echo
echo checking that our registered Global Daemons plist matches expected...
diff $TS_CELLAR/$TS_VER/$TS_PLIST $INSTALLED_PLIST_DIR/$TS_PLIST

echo
echo brew service shows tailscale as started...
$SUDO brew services list | grep tailscale

echo
echo launchctl lists tailscale...
$SUDO launchctl list | grep tailscale

echo
echo tailscale version...
$TS_BIN/tailscale --version # should be found, executable and exit 0

echo
echo tailscale netcheck...
$TS_BIN/tailscale netcheck # should be found, executable and exit 0

echo
echo tailscale up \(and wait for human to do the auth dance if needed\)...
brew/up.sh # this will block, displaying the auth url, if it needs to auth. then/or proceed once happy

echo
echo list all tailscale files installed or generated...
$SUDO find $BREW | grep -i tailscale

echo
echo pausing to give tailscaled enough time to finish post-auth setup...
sleep 15 # otherwise some of my early status pings sometimes fail (esp hello.ipn.dev; then work on all subsequent attempts)
echo
echo status...
brew/status.sh

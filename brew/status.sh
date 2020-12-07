#!/usr/bin/env sh
set -u

eval $(brew/vars.sh)

# everything you see below is not expected to be rigorous, or decisive or even always relevant,
# but gives useful data and a nice smoke test of a candidate install for the brew maintainer

echo file checks \(exes, state, socket\)...
ls -la $TS_BIN/tailscale*
ls -l $TS_STATE
ls -l $TS_SOCK

echo
$TS_BIN/tailscale version

echo
$TS_BIN/tailscale netcheck

echo
echo tailscale status:
sudo $TS_BIN/tailscale -socket=$TS_SOCK status

echo
ifconfig -r en0

# TODO(mkramlich): learn the utun<NUM> it picked and handle tun/gateway right everywhere below

echo
ifconfig -r utun5

echo Routing\\n

echo \(Destination        Gateway            Flags        Netif Expire\):
netstat -r -n -f inet | grep utun

echo IPv4 routes:
netstat -r -n -f inet -ll
echo IPv4 route stats:
netstat -r -n -f inet -s
echo IPv6 routes:
netstat -r -n -f inet6 -ll
echo IPv6 route stats:
netstat -r -n -f inet6 -s

echo
echo checking if host IP forwarding is enabled...
sysctl -a | grep forward

echo
echo pinging the TS login/coord server...
ping -c1 login.tailscale.com # only to help rule out other issues during a brew test

echo
echo pinging the TS log server...
ping -c1 log.tailscale.io

echo
echo pinging the common hello node by name...
ping -c1 hello.ipn.dev # a nice smoke test
echo ... by tailscale ping DNS...
sudo $TS_BIN/tailscale -socket=$TS_SOCK ping -c 1 hello.ipn.dev
echo ... by ping IPv4...
ping -c1 100.101.102.103
echo ... by tailscale ping IPv4...
sudo $TS_BIN/tailscale -socket=$TS_SOCK ping -c 1 100.101.102.103
echo ... by ping6 IPv6...
ping6 -c1 fd7a:115c:a1e0:ab12:4843:cd96:6265:6667 # TODO(mkramlich): do right or drop

# TODO(mkramlich): below is personal node Ts addr, so either drop or make overridable by maintainer
echo
echo pinging my android node...
ping -c1 100.119.147.125
sudo $TS_BIN/tailscale -socket=$TS_SOCK ping -c 1 100.119.147.125
ping6 -c1 fd7a:115c:a1e0:ab12:4843:cd96:6277:937d

echo
echo check stderr log for any recent error, warn, fail, missing or weird...
# NOTE we dont do a 'set -e' style fail assert on this error log tail here because this is for human consumption,
# plus, not quite sure/ready about what specifc messages are scary enough to potentially fail a test
#sudo grep -i -e error -e warn -e fail -e missing -e weird $TS_LOG_DIR/tailscaled-stderr.log
sudo tail -100 $TS_LOG_DIR/tailscaled-stderr.log | grep -i -e error -e warn -e fail -e missing -e weird


// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"bytes"
	"log"
	"net/netip"
	"os/exec"
	"sync/atomic"

	"go4.org/mem"
	"golang.org/x/sys/unix"
	"tailscale.com/net/netaddr"
	"tailscale.com/syncs"
	"tailscale.com/util/lineiter"
)

var (
	lastKnownDefaultRouteIfName syncs.AtomicValue[string]
)

var procNetRoutePath = "/proc/net/route"

// maxProcNetRouteRead is the max number of lines to read from
// /proc/net/route looking for a default route.
const maxProcNetRouteRead = 1000

func init() {
	likelyHomeRouterIP = likelyHomeRouterIPAndroid
}

var procNetRouteErr atomic.Bool

/*
Parse 10.0.0.1 out of:

$ cat /proc/net/route
Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
ens18   00000000        0100000A        0003    0       0       0       00000000        0       0       0
ens18   0000000A        00000000        0001    0       0       0       0000FFFF        0       0       0
*/
func likelyHomeRouterIPAndroid() (ret netip.Addr, myIP netip.Addr, ok bool) {
	if procNetRouteErr.Load() {
		// If we failed to read /proc/net/route previously, don't keep trying.
		return likelyHomeRouterIPHelper()
	}
	lineNum := 0
	var f []mem.RO
	for lr := range lineiter.File(procNetRoutePath) {
		line, err := lr.Value()
		if err != nil {
			procNetRouteErr.Store(true)
			return likelyHomeRouterIP()
		}

		lineNum++
		if lineNum == 1 {
			// Skip header line.
			continue
		}
		if lineNum > maxProcNetRouteRead {
			break
		}
		f = mem.AppendFields(f[:0], mem.B(line))
		if len(f) < 4 {
			continue
		}
		gwHex, flagsHex := f[2], f[3]
		flags, err := mem.ParseUint(flagsHex, 16, 16)
		if err != nil {
			continue // ignore error, skip line and keep going
		}
		if flags&(unix.RTF_UP|unix.RTF_GATEWAY) != unix.RTF_UP|unix.RTF_GATEWAY {
			continue
		}
		ipu32, err := mem.ParseUint(gwHex, 16, 32)
		if err != nil {
			continue // ignore error, skip line and keep going
		}
		ip := netaddr.IPv4(byte(ipu32), byte(ipu32>>8), byte(ipu32>>16), byte(ipu32>>24))
		if ip.IsPrivate() {
			ret = ip
			break
		}
	}
	if ret.IsValid() {
		// Try to get the local IP of the interface associated with
		// this route to short-circuit finding the IP associated with
		// this gateway. This isn't fatal if it fails.
		if len(f) > 0 && !disableLikelyHomeRouterIPSelf() {
			ForeachInterface(func(ni Interface, pfxs []netip.Prefix) {
				// Ensure this is the same interface
				if !f[0].EqualString(ni.Name) {
					return
				}

				// Find the first IPv4 address and use it.
				for _, pfx := range pfxs {
					if addr := pfx.Addr(); addr.Is4() {
						myIP = addr
						break
					}
				}
			})
		}

		return ret, myIP, true
	}
	if lineNum >= maxProcNetRouteRead {
		// If we went over our line limit without finding an answer, assume
		// we're a big fancy Linux router (or at least not a home system)
		// and set the error bit so we stop trying this in the future (and wasting CPU).
		// See https://github.com/tailscale/tailscale/issues/7621.
		//
		// Remember that "likelyHomeRouterIP" exists purely to find the port
		// mapping service (UPnP, PMP, PCP) often present on a home router. If we hit
		// the route (line) limit without finding an answer, we're unlikely to ever
		// find one in the future.
		procNetRouteErr.Store(true)
	}
	return netip.Addr{}, netip.Addr{}, false
}

// Android apps don't have permission to read /proc/net/route, at
// least on Google devices and the Android emulator.
func likelyHomeRouterIPHelper() (ret netip.Addr, _ netip.Addr, ok bool) {
	cmd := exec.Command("/system/bin/ip", "route", "show", "table", "0")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		log.Printf("interfaces: running /system/bin/ip: %v", err)
		return
	}
	// Search for line like "default via 10.0.2.2 dev radio0 table 1016 proto static mtu 1500 "
	for lr := range lineiter.Reader(out) {
		line, err := lr.Value()
		if err != nil {
			break
		}
		const pfx = "default via "
		if !mem.HasPrefix(mem.B(line), mem.S(pfx)) {
			continue
		}
		line = line[len(pfx):]
		sp := bytes.IndexByte(line, ' ')
		if sp == -1 {
			continue
		}
		ipb := line[:sp]
		if ip, err := netip.ParseAddr(string(ipb)); err == nil && ip.Is4() {
			ret = ip
			log.Printf("interfaces: found Android default route %v", ip)
		}
	}
	cmd.Process.Kill()
	cmd.Wait()
	return ret, netip.Addr{}, ret.IsValid()
}

// UpdateLastKnownDefaultRouteInterface is called by libtailscale in the Android app when
// the connectivity manager detects a network path transition. If ifName is "", network has been lost.
// After updating the interface, Android calls Monitor.InjectEvent(), triggering a link change.
func UpdateLastKnownDefaultRouteInterface(ifName string) {
	if old := lastKnownDefaultRouteIfName.Swap(ifName); old != ifName {
		log.Printf("defaultroute: update from Android, ifName = %s (was %s)", ifName, old)
	}
}

func defaultRoute() (d DefaultRouteDetails, err error) {
	if ifName := lastKnownDefaultRouteIfName.Load(); ifName != "" {
		d.InterfaceName = ifName
	}
	return d, nil
}

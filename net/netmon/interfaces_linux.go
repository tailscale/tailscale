// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package netmon

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"go4.org/mem"
	"golang.org/x/sys/unix"
	"tailscale.com/net/netaddr"
	"tailscale.com/util/lineiter"
)

func init() {
	likelyHomeRouterIP = likelyHomeRouterIPLinux
}

var procNetRouteErr atomic.Bool

/*
Parse 10.0.0.1 out of:

$ cat /proc/net/route
Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
ens18   00000000        0100000A        0003    0       0       0       00000000        0       0       0
ens18   0000000A        00000000        0001    0       0       0       0000FFFF        0       0       0
*/
func likelyHomeRouterIPLinux() (ret netip.Addr, myIP netip.Addr, ok bool) {
	if procNetRouteErr.Load() {
		// If we failed to read /proc/net/route previously, don't keep trying.
		return ret, myIP, false
	}
	lineNum := 0
	var f []mem.RO
	for lr := range lineiter.File(procNetRoutePath) {
		line, err := lr.Value()
		if err != nil {
			procNetRouteErr.Store(true)
			log.Printf("interfaces: failed to read /proc/net/route: %v", err)
			return ret, myIP, false
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

func defaultRoute() (d DefaultRouteDetails, err error) {
	v, err := defaultRouteInterfaceProcNet()
	if err == nil {
		d.InterfaceName = v
		return d, nil
	}
	// Issue 4038: the default route (such as on Unifi UDM Pro)
	// might be in a non-default table, so it won't show up in
	// /proc/net/route. Use netlink to find the default route.
	//
	// TODO(bradfitz): this allocates a fair bit. We should track
	// this in net/interfaces/monitor instead and have
	// interfaces.GetState take a netmon.Monitor or similar so the
	// routing table can be cached and the monitor's existing
	// subscription to route changes can update the cached state,
	// rather than querying the whole thing every time like
	// defaultRouteFromNetlink does.
	//
	// Then we should just always try to use the cached route
	// table from netlink every time, and only use /proc/net/route
	// as a fallback for weird environments where netlink might be
	// banned but /proc/net/route is emulated (e.g. stuff like
	// Cloud Run?).
	return defaultRouteFromNetlink()
}

func defaultRouteFromNetlink() (d DefaultRouteDetails, err error) {
	c, err := rtnetlink.Dial(&netlink.Config{Strict: true})
	if err != nil {
		return d, fmt.Errorf("defaultRouteFromNetlink: Dial: %w", err)
	}
	defer c.Close()
	rms, err := c.Route.List()
	if err != nil {
		return d, fmt.Errorf("defaultRouteFromNetlink: List: %w", err)
	}
	for _, rm := range rms {
		if rm.Attributes.Gateway == nil {
			// A default route has a gateway. If it doesn't, skip it.
			continue
		}
		if rm.Attributes.Dst != nil {
			// A default route has a nil destination to mean anything
			// so ignore any route for a specific destination.
			// TODO(bradfitz): better heuristic?
			// empirically this seems like enough.
			continue
		}
		// TODO(bradfitz): care about address family, if
		// callers ever start caring about v4-vs-v6 default
		// route differences.
		idx := int(rm.Attributes.OutIface)
		if idx == 0 {
			continue
		}
		if iface, err := net.InterfaceByIndex(idx); err == nil {
			d.InterfaceName = iface.Name
			d.InterfaceIndex = idx
			return d, nil
		}
	}
	return d, errNoDefaultRoute
}

var zeroRouteBytes = []byte("00000000")
var procNetRoutePath = "/proc/net/route"

// maxProcNetRouteRead is the max number of lines to read from
// /proc/net/route looking for a default route.
const maxProcNetRouteRead = 1000

var errNoDefaultRoute = errors.New("no default route found")

func defaultRouteInterfaceProcNetInternal(bufsize int) (string, error) {
	f, err := os.Open(procNetRoutePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, bufsize)
	lineNum := 0
	for {
		lineNum++
		line, err := br.ReadSlice('\n')
		if err == io.EOF || lineNum > maxProcNetRouteRead {
			return "", errNoDefaultRoute
		}
		if err != nil {
			return "", err
		}
		if !bytes.Contains(line, zeroRouteBytes) {
			continue
		}
		fields := strings.Fields(string(line))
		ifc := fields[0]
		ip := fields[1]
		netmask := fields[7]

		if strings.HasPrefix(ifc, "tailscale") ||
			strings.HasPrefix(ifc, "wg") {
			continue
		}
		if ip == "00000000" && netmask == "00000000" {
			// default route
			return ifc, nil // interface name
		}
	}
}

// returns string interface name and an error.
// io.EOF: full route table processed, no default route found.
// other io error: something went wrong reading the route file.
func defaultRouteInterfaceProcNet() (string, error) {
	rc, err := defaultRouteInterfaceProcNetInternal(128)
	if rc == "" && (errors.Is(err, io.EOF) || err == nil) {
		// https://github.com/google/gvisor/issues/5732
		// On a regular Linux kernel you can read the first 128 bytes of /proc/net/route,
		// then come back later to read the next 128 bytes and so on.
		//
		// In Google Cloud Run, where /proc/net/route comes from gVisor, you have to
		// read it all at once. If you read only the first few bytes then the second
		// read returns 0 bytes no matter how much originally appeared to be in the file.
		//
		// At the time of this writing (Mar 2021) Google Cloud Run has eth0 and eth1
		// with a 384 byte /proc/net/route. We allocate a large buffer to ensure we'll
		// read it all in one call.
		return defaultRouteInterfaceProcNetInternal(4096)
	}
	return rc, err
}

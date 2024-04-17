// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package interfaces

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
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"go4.org/mem"
	"golang.org/x/sys/unix"
	"tailscale.com/net/netaddr"
	"tailscale.com/util/lineread"
)

func init() {
	likelyHomeRouterIP = likelyHomeRouterIPLinux
}

var procNetRouteErr atomic.Bool

// errStopReading is a sentinel error value used internally by
// lineread.File callers to stop reading. It doesn't escape to
// callers/users.
var errStopReading = errors.New("stop reading")

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
		// But if we're on Android, go into the Android path.
		if runtime.GOOS == "android" {
			return likelyHomeRouterIPAndroid()
		}
		return ret, myIP, false
	}
	lineNum := 0
	var f []mem.RO
	err := lineread.File(procNetRoutePath, func(line []byte) error {
		lineNum++
		if lineNum == 1 {
			// Skip header line.
			return nil
		}
		if lineNum > maxProcNetRouteRead {
			return errStopReading
		}
		f = mem.AppendFields(f[:0], mem.B(line))
		if len(f) < 4 {
			return nil
		}
		gwHex, flagsHex := f[2], f[3]
		flags, err := mem.ParseUint(flagsHex, 16, 16)
		if err != nil {
			return nil // ignore error, skip line and keep going
		}
		if flags&(unix.RTF_UP|unix.RTF_GATEWAY) != unix.RTF_UP|unix.RTF_GATEWAY {
			return nil
		}
		ipu32, err := mem.ParseUint(gwHex, 16, 32)
		if err != nil {
			return nil // ignore error, skip line and keep going
		}
		ip := netaddr.IPv4(byte(ipu32), byte(ipu32>>8), byte(ipu32>>16), byte(ipu32>>24))
		if ip.IsPrivate() {
			ret = ip
			return errStopReading
		}
		return nil
	})
	if errors.Is(err, errStopReading) {
		err = nil
	}
	if err != nil {
		procNetRouteErr.Store(true)
		if runtime.GOOS == "android" {
			return likelyHomeRouterIPAndroid()
		}
		log.Printf("interfaces: failed to read /proc/net/route: %v", err)
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
func likelyHomeRouterIPAndroid() (ret netip.Addr, _ netip.Addr, ok bool) {
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
	lineread.Reader(out, func(line []byte) error {
		const pfx = "default via "
		if !mem.HasPrefix(mem.B(line), mem.S(pfx)) {
			return nil
		}
		line = line[len(pfx):]
		sp := bytes.IndexByte(line, ' ')
		if sp == -1 {
			return nil
		}
		ipb := line[:sp]
		if ip, err := netip.ParseAddr(string(ipb)); err == nil && ip.Is4() {
			ret = ip
			log.Printf("interfaces: found Android default route %v", ip)
		}
		return nil
	})
	cmd.Process.Kill()
	cmd.Wait()
	return ret, netip.Addr{}, ret.IsValid()
}

func defaultRoute() (d DefaultRouteDetails, err error) {
	v, err := defaultRouteInterfaceProcNet()
	if err == nil {
		d.InterfaceName = v
		return d, nil
	}
	if runtime.GOOS == "android" {
		v, err = defaultRouteInterfaceAndroidIPRoute()
		d.InterfaceName = v
		return d, err
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

// defaultRouteInterfaceAndroidIPRoute tries to find the machine's default route interface name
// by parsing the "ip route" command output. We use this on Android where /proc/net/route
// can be missing entries or have locked-down permissions.
// See also comments in https://github.com/tailscale/tailscale/pull/666.
func defaultRouteInterfaceAndroidIPRoute() (ifname string, err error) {
	cmd := exec.Command("/system/bin/ip", "route", "show", "table", "0")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		log.Printf("interfaces: running /system/bin/ip: %v", err)
		return "", err
	}
	// Search for line like "default via 10.0.2.2 dev radio0 table 1016 proto static mtu 1500 "
	lineread.Reader(out, func(line []byte) error {
		const pfx = "default via "
		if !mem.HasPrefix(mem.B(line), mem.S(pfx)) {
			return nil
		}
		ff := strings.Fields(string(line))
		for i, v := range ff {
			if i > 0 && ff[i-1] == "dev" && ifname == "" {
				ifname = v
			}
		}
		return nil
	})
	cmd.Process.Kill()
	cmd.Wait()
	if ifname == "" {
		return "", errors.New("no default routes found")
	}
	return ifname, nil
}

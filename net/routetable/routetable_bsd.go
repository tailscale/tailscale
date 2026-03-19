// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || freebsd || openbsd

package routetable

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

type RouteEntryBSD struct {
	// GatewayInterface is the name of the interface specified as a gateway
	// for this route, if any.
	GatewayInterface string
	// GatewayIdx is the index of the interface specified as a gateway for
	// this route, if any.
	GatewayIdx int
	// GatewayAddr is the link-layer address of the gateway for this route,
	// if any.
	GatewayAddr string
	// Flags contains a string representation of common flags for this
	// route.
	Flags []string
	// RawFlags contains the raw flags that were returned by the operating
	// system for this route.
	RawFlags int
}

// Format implements the fmt.Formatter interface.
func (r RouteEntryBSD) Format(f fmt.State, verb rune) {
	logger.ArgWriter(func(w *bufio.Writer) {
		var pstart bool
		pr := func(format string, args ...any) {
			if pstart {
				fmt.Fprintf(w, ", "+format, args...)
			} else {
				fmt.Fprintf(w, format, args...)
				pstart = true
			}
		}

		w.WriteString("{")
		if r.GatewayInterface != "" {
			pr("GatewayInterface: %s", r.GatewayInterface)
		}
		if r.GatewayIdx > 0 {
			pr("GatewayIdx: %d", r.GatewayIdx)
		}
		if r.GatewayAddr != "" {
			pr("GatewayAddr: %s", r.GatewayAddr)
		}
		pr("Flags: %v", r.Flags)

		unknownFlags := r.RawFlags
		for fv := range flags {
			if r.RawFlags&fv == fv {
				unknownFlags &= ^fv
			}
		}
		if unknownFlags != 0 {
			pr("UnknownFlags: %x ", unknownFlags)
		}

		w.WriteString("}")
	}).Format(f, verb)
}

// ipFromRMAddr returns a netip.Addr converted from one of the
// route.Inet{4,6}Addr types.
func ipFromRMAddr(ifs map[int]netmon.Interface, addr any) netip.Addr {
	switch v := addr.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(v.IP)

	case *route.Inet6Addr:
		ip := netip.AddrFrom16(v.IP)
		if v.ZoneID != 0 {
			if iif, ok := ifs[v.ZoneID]; ok {
				ip = ip.WithZone(iif.Name)
			} else {
				ip = ip.WithZone(fmt.Sprint(v.ZoneID))
			}
		}

		return ip
	}

	return netip.Addr{}
}

// populateGateway populates gateway fields on a RouteEntry/RouteEntryBSD.
func populateGateway(re *RouteEntry, reSys *RouteEntryBSD, ifs map[int]netmon.Interface, addr any) {
	// If the address type has a valid IP, use that.
	if ip := ipFromRMAddr(ifs, addr); ip.IsValid() {
		re.Gateway = ip
		return
	}

	switch v := addr.(type) {
	case *route.LinkAddr:
		reSys.GatewayIdx = v.Index
		if iif, ok := ifs[v.Index]; ok {
			reSys.GatewayInterface = iif.Name
		}
		var sb strings.Builder
		for i, x := range v.Addr {
			if i != 0 {
				sb.WriteByte(':')
			}
			fmt.Fprintf(&sb, "%02x", x)
		}
		reSys.GatewayAddr = sb.String()
	}
}

// populateDestination populates the 'Dst' field on a RouteEntry based on the
// RouteMessage's destination and netmask fields.
func populateDestination(re *RouteEntry, ifs map[int]netmon.Interface, rm *route.RouteMessage) {
	dst := rm.Addrs[unix.RTAX_DST]
	if dst == nil {
		return
	}

	ip := ipFromRMAddr(ifs, dst)
	if !ip.IsValid() {
		return
	}

	if ip.Is4() {
		re.Family = 4
	} else {
		re.Family = 6
	}
	re.Dst = RouteDestination{
		Prefix: netip.PrefixFrom(ip, 32), // default if nothing more specific
	}

	// If the RTF_HOST flag is set, then this is a host route and there's
	// no netmask in this RouteMessage.
	if rm.Flags&unix.RTF_HOST != 0 {
		return
	}

	// As above if there's no netmask in the list of addrs
	if len(rm.Addrs) < unix.RTAX_NETMASK || rm.Addrs[unix.RTAX_NETMASK] == nil {
		return
	}

	nm := ipFromRMAddr(ifs, rm.Addrs[unix.RTAX_NETMASK])
	if !ip.IsValid() {
		return
	}

	// Count the number of bits in the netmask IP and use that to make our prefix.
	ones, _ /* bits */ := net.IPMask(nm.AsSlice()).Size()

	// Print this ourselves instead of using netip.Prefix so that we don't
	// lose the zone (since netip.Prefix strips that).
	//
	// NOTE(andrew): this doesn't print the same values as the 'netstat' tool
	// for some addresses on macOS, and I have no idea why. Specifically,
	// 'netstat -rn' will show something like:
	//    ff00::/8   ::1      UmCI     lo0
	//
	// But we will get:
	//    destination=ff00::/40 [...]
	//
	// The netmask that we get back from FetchRIB has 32 more bits in it
	// than netstat prints, but only for multicast routes.
	//
	// For consistency's sake, we're going to do the same here so that we
	// get the same values as netstat returns.
	if runtime.GOOS == "darwin" && ip.Is6() && ip.IsMulticast() && ones > 32 {
		ones -= 32
	}
	re.Dst = RouteDestination{
		Prefix: netip.PrefixFrom(ip, ones),
		Zone:   ip.Zone(),
	}
}

// routeEntryFromMsg returns a RouteEntry from a single route.Message
// returned by the operating system.
func routeEntryFromMsg(ifsByIdx map[int]netmon.Interface, msg route.Message) (RouteEntry, bool) {
	rm, ok := msg.(*route.RouteMessage)
	if !ok {
		return RouteEntry{}, false
	}

	// Ignore things that we don't understand
	if rm.Version < 3 || rm.Version > 5 {
		return RouteEntry{}, false
	}
	if rm.Type != rmExpectedType {
		return RouteEntry{}, false
	}
	if len(rm.Addrs) < unix.RTAX_GATEWAY {
		return RouteEntry{}, false
	}

	if rm.Flags&skipFlags != 0 {
		return RouteEntry{}, false
	}

	reSys := RouteEntryBSD{
		RawFlags: rm.Flags,
	}
	for fv, fs := range flags {
		if rm.Flags&fv == fv {
			reSys.Flags = append(reSys.Flags, fs)
		}
	}
	sort.Strings(reSys.Flags)

	re := RouteEntry{}
	hasFlag := func(f int) bool { return rm.Flags&f != 0 }
	switch {
	case hasFlag(unix.RTF_LOCAL):
		re.Type = RouteTypeLocal
	case hasFlag(unix.RTF_BROADCAST):
		re.Type = RouteTypeBroadcast
	case hasFlag(unix.RTF_MULTICAST):
		re.Type = RouteTypeMulticast

	// From the manpage: "host entry (net otherwise)"
	case !hasFlag(unix.RTF_HOST):
		re.Type = RouteTypeUnicast

	default:
		re.Type = RouteTypeOther
	}
	populateDestination(&re, ifsByIdx, rm)
	if unix.RTAX_GATEWAY < len(rm.Addrs) {
		populateGateway(&re, &reSys, ifsByIdx, rm.Addrs[unix.RTAX_GATEWAY])
	}

	if outif, ok := ifsByIdx[rm.Index]; ok {
		re.Interface = outif.Name
	}

	re.Sys = reSys
	return re, true
}

// Get returns route entries from the system route table, limited to at most
// 'max' results.
func Get(max int) ([]RouteEntry, error) {
	// Fetching the list of interfaces can race with fetching our route
	// table, but we do it anyway since it's helpful for debugging.
	ifs, err := netmon.GetInterfaceList()
	if err != nil {
		return nil, err
	}

	ifsByIdx := make(map[int]netmon.Interface)
	for _, iif := range ifs {
		ifsByIdx[iif.Index] = iif
	}

	rib, err := route.FetchRIB(syscall.AF_UNSPEC, ribType, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(parseType, rib)
	if err != nil {
		return nil, err
	}

	var ret []RouteEntry
	for _, m := range msgs {
		re, ok := routeEntryFromMsg(ifsByIdx, m)
		if ok {
			ret = append(ret, re)
			if len(ret) == max {
				break
			}
		}
	}
	return ret, nil
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package via64 records which 4via6 prefixes the kernel translates (see net/via64/xlat), so that netstack leaves those packets to it.
//
// The record is process-wide because its writer (the Linux router) and its reader (netstack) share no object; it could move to tsd.System.
package via64

import (
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"

	"tailscale.com/net/ipset"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
)

type kernelState struct {
	contains func(netip.Addr) bool
	udp      bool
}

type hostState struct {
	addrs       map[netip.Addr]bool
	inContainer func(netip.Addr) bool // on this host's Docker or libvirt networks
}

var (
	kernel atomic.Pointer[kernelState]
	host   atomic.Pointer[hostState]
)

// SetKernelHandled sets the via prefixes the kernel translates, and whether that includes UDP. Empty means netstack handles all 4via6, the default.
func SetKernelHandled(prefixes []netip.Prefix, udp bool) {
	if len(prefixes) == 0 {
		kernel.Store(nil)
		return
	}
	kernel.Store(&kernelState{contains: ipset.NewContainsIPFunc(views.SliceOf(slices.Clone(prefixes))), udp: udp})
}

// SetHostInterfaces records this host's interface addresses. 4via6 to the host itself, or to its Docker and libvirt networks, stays on netstack: through the kernel it would meet the host's INPUT policy, or Docker's and libvirt's rules, which only accept forwarded traffic arriving on the bridge.
func SetHostInterfaces(ifaces map[string][]netip.Prefix) {
	h := &hostState{addrs: map[netip.Addr]bool{}}
	var guests []netip.Prefix
	for name, pfxs := range ifaces {
		for _, p := range pfxs {
			if !p.Addr().Is4() {
				continue
			}
			h.addrs[p.Addr()] = true
			if isGuestBridge(name) {
				guests = append(guests, p.Masked())
			}
		}
	}
	h.inContainer = ipset.NewContainsIPFunc(views.SliceOf(guests))
	host.Store(h)
}

// isGuestBridge reports whether name is a Docker bridge (docker0, or br- and a 12-hex-digit network ID) or a libvirt one (virbrN).
func isGuestBridge(name string) bool {
	if name == "docker0" {
		return true
	}
	if id, ok := strings.CutPrefix(name, "br-"); ok {
		return len(id) == 12 && strings.Trim(id, "0123456789abcdef") == ""
	}
	if n, ok := strings.CutPrefix(name, "virbr"); ok {
		return n != "" && strings.Trim(n, "0123456789") == ""
	}
	return false
}

// KernelHandles reports whether the kernel translates traffic of protocol proto to the via address ip.
func KernelHandles(ip netip.Addr, proto ipproto.Proto) bool {
	s := kernel.Load()
	if s == nil || !s.contains(ip) {
		return false
	}
	switch proto {
	case ipproto.TCP, ipproto.ICMPv6:
	case ipproto.UDP, ipproto.Fragment: // later fragments are almost always UDP
		if !s.udp {
			return false
		}
	default:
		return false
	}
	target := tsaddr.UnmapVia(ip)
	if !target.IsGlobalUnicast() { // the kernel would not forward to loopback, link-local or broadcast; netstack dials them
		return false
	}
	if h := host.Load(); h != nil && (h.addrs[target] || h.inContainer(target)) {
		return false
	}
	return true
}

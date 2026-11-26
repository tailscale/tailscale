// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Common code for FreeBSD and Darwin. This might also work on other
// BSD systems (e.g. OpenBSD) but has not been tested.

//go:build darwin || freebsd || openbsd

package netmon

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/net/netaddr"
)

// ErrNoGatewayIndexFound is returned by DefaultRouteInterfaceIndex when no
// default route is found.
var ErrNoGatewayIndexFound = errors.New("no gateway index found")

// DefaultRouteInterfaceIndex returns the index of the network interface that
// owns the default route. It returns the first IPv4 or IPv6 default route it
// finds (it does not prefer one or the other).
func DefaultRouteInterfaceIndex() (int, error) {
	// $ netstat -nr
	// Routing tables
	// Internet:
	// Destination        Gateway            Flags        Netif Expire
	// default            10.0.0.1           UGSc           en0         <-- want this one
	// default            10.0.0.1           UGScI          en1

	// From man netstat:
	// U       RTF_UP           Route usable
	// G       RTF_GATEWAY      Destination requires forwarding by intermediary
	// S       RTF_STATIC       Manually added
	// c       RTF_PRCLONING    Protocol-specified generate new routes on use
	// I       RTF_IFSCOPE      Route is associated with an interface scope

	rib, err := fetchRoutingTable()
	if err != nil {
		return 0, fmt.Errorf("route.FetchRIB: %w", err)
	}
	msgs, err := parseRoutingTable(rib)
	if err != nil {
		return 0, fmt.Errorf("route.ParseRIB: %w", err)
	}
	if rm := findDefaultGatewayRoute(msgs); rm != nil {
		if delegatedIndex, err := getDelegatedInterface(rm.Index); err == nil && delegatedIndex != 0 {
			return delegatedIndex, nil
		} else if err != nil {
			log.Printf("interfaces_bsd: could not get delegated interface: %v", err)
		}
		return rm.Index, nil
	}
	return 0, ErrNoGatewayIndexFound
}

// findDefaultGatewayRoute returns the default route in msgs that has a
// gateway, or nil if there is none.
//
// Unscoped routes are preferred. If there are none, it falls back to the first
// interface-scoped (RTF_IFSCOPE) one. That happens when a full-tunnel VPN or
// TUN-mode proxy (OpenVPN, Clash, ...) installs an interface-route default
// (no gateway) as the global default: the OS then demotes the physical
// interface's default route (e.g. en0 via the home router) to a scoped one,
// which is still the right interface to bind our own sockets to.
func findDefaultGatewayRoute(msgs []route.Message) *route.RouteMessage {
	var scoped *route.RouteMessage
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || !isDefaultRouteWithGateway(rm) {
			continue
		}
		if rm.Flags&rtfIfScope == 0 {
			return rm
		}
		if scoped == nil {
			scoped = rm
		}
	}
	return scoped
}

func init() {
	likelyHomeRouterIP = likelyHomeRouterIPBSDFetchRIB
}

func likelyHomeRouterIPBSDFetchRIB() (ret, myIP netip.Addr, ok bool) {
	rib, err := fetchRoutingTable()
	if err != nil {
		log.Printf("routerIP/FetchRIB: %v", err)
		return ret, myIP, false
	}
	msgs, err := parseRoutingTable(rib)
	if err != nil {
		log.Printf("routerIP/ParseRIB: %v", err)
		return ret, myIP, false
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		if !isDefaultGateway(rm) {
			continue
		}

		gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
		if !ok {
			continue
		}
		// If the route entry has an interface address associated with
		// it, then parse and return that. This is optional.
		if len(rm.Addrs) >= unix.RTAX_IFA {
			if addr, ok := rm.Addrs[unix.RTAX_IFA].(*route.Inet4Addr); ok {
				myIP = netaddr.IPv4(addr.IP[0], addr.IP[1], addr.IP[2], addr.IP[3])
			}
		}

		return netaddr.IPv4(gw.IP[0], gw.IP[1], gw.IP[2], gw.IP[3]), myIP, true
	}

	return ret, myIP, false
}

var v4default = [4]byte{0, 0, 0, 0}
var v6default = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// rtfIfScope is RTF_IFSCOPE, defined locally because FreeBSD does not have
// unix.RTF_IFSCOPE.
const rtfIfScope = 0x1000000

// isDefaultGateway reports whether rm is an unscoped default route with a
// gateway.
func isDefaultGateway(rm *route.RouteMessage) bool {
	return rm.Flags&rtfIfScope == 0 && isDefaultRouteWithGateway(rm)
}

// isDefaultRouteWithGateway reports whether rm is a default route (0.0.0.0/0
// or ::/0) with a gateway, scoped to an interface or not.
func isDefaultRouteWithGateway(rm *route.RouteMessage) bool {
	if rm.Flags&unix.RTF_GATEWAY == 0 {
		return false
	}

	// Addrs is [RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK, ...]
	if len(rm.Addrs) <= unix.RTAX_NETMASK {
		return false
	}

	dst := rm.Addrs[unix.RTAX_DST]
	netmask := rm.Addrs[unix.RTAX_NETMASK]
	if dst == nil || netmask == nil {
		return false
	}

	if dst.Family() == syscall.AF_INET && netmask.Family() == syscall.AF_INET {
		dstAddr, dstOk := dst.(*route.Inet4Addr)
		nmAddr, nmOk := netmask.(*route.Inet4Addr)
		if dstOk && nmOk && dstAddr.IP == v4default && nmAddr.IP == v4default {
			return true
		}
	}

	if dst.Family() == syscall.AF_INET6 && netmask.Family() == syscall.AF_INET6 {
		dstAddr, dstOk := dst.(*route.Inet6Addr)
		nmAddr, nmOk := netmask.(*route.Inet6Addr)
		if dstOk && nmOk && dstAddr.IP == v6default && nmAddr.IP == v6default {
			return true
		}
	}

	return false
}

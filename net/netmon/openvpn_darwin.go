// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package netmon

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
)

// hasOpenVPNRoutesDarwin checks for the characteristic OpenVPN routes (0/1 and 128.0/1)
// by examining the system route table using the same approach as the routetable package.
func hasOpenVPNRoutesDarwin() bool {
	// Fetch the kernel route table
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, unix.NET_RT_DUMP2, 0)
	if err != nil {
		if envknob.Bool("TS_DEBUG_OPENVPN") {
			fmt.Printf("netmon: FetchRIB failed: %v\n", err)
		}
		return false
	}

	msgs, err := route.ParseRIB(unix.NET_RT_IFLIST2, rib)
	if err != nil {
		if envknob.Bool("TS_DEBUG_OPENVPN") {
			fmt.Printf("netmon: ParseRIB failed: %v\n", err)
		}
		return false
	}

	// Track which interface index has each route
	var zeroRouteIfIdx, halfRouteIfIdx int

	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Type != unix.RTM_GET2 {
			continue
		}

		// Need at least destination and netmask
		if len(rm.Addrs) <= unix.RTAX_NETMASK {
			continue
		}

		// Get destination address
		dstAddr, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		if !ok {
			continue
		}
		dst := netip.AddrFrom4(dstAddr.IP)

		// Get netmask
		maskAddr, ok := rm.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr)
		if !ok {
			continue
		}
		mask := net.IPMask(maskAddr.IP[:])
		ones, bits := mask.Size()

		// Check if this is a /1 route (1 bit set in netmask)
		if bits != 32 || ones != 1 {
			continue
		}

		// Check if this is one of the OpenVPN characteristic routes
		switch dst.String() {
		case "0.0.0.0":
			zeroRouteIfIdx = rm.Index
			if envknob.Bool("TS_DEBUG_OPENVPN") {
				fmt.Printf("netmon: found 0.0.0.0/1 route via interface index %d\n", rm.Index)
			}
		case "128.0.0.0":
			halfRouteIfIdx = rm.Index
			if envknob.Bool("TS_DEBUG_OPENVPN") {
				fmt.Printf("netmon: found 128.0.0.0/1 route via interface index %d\n", rm.Index)
			}
		}
	}

	// Both routes must exist and use the same interface
	if zeroRouteIfIdx != 0 && zeroRouteIfIdx == halfRouteIfIdx {
		// Verify the interface is a utun interface
		if iface, err := net.InterfaceByIndex(zeroRouteIfIdx); err == nil && strings.HasPrefix(iface.Name, "utun") {
			if envknob.Bool("TS_DEBUG_OPENVPN") {
				fmt.Printf("netmon: confirmed OpenVPN interface: %s (has both characteristic /1 routes)\n", iface.Name)
			}
			return true
		}
	}

	if envknob.Bool("TS_DEBUG_OPENVPN") {
		fmt.Printf("netmon: OpenVPN routes not found: 0/1 on if%d, 128.0/1 on if%d\n", zeroRouteIfIdx, halfRouteIfIdx)
	}
	return false
}

// isOpenVPNInterfaceDarwin checks if an interface is an OpenVPN interface
// by verifying it's a utun interface with the characteristic OpenVPN routes.
func isOpenVPNInterfaceDarwin(nif *net.Interface) bool {
	// Only check utun interfaces
	if !strings.HasPrefix(nif.Name, "utun") {
		return false
	}

	// Must be up and have addresses
	if nif.Flags&net.FlagUp == 0 {
		return false
	}

	addrs, err := nif.Addrs()
	if err != nil || len(addrs) == 0 {
		return false
	}

	// Check if this interface has private IP addresses (typical of VPN tunnels)
	hasPrivateIP := false
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ip, ok := netip.AddrFromSlice(ipnet.IP)
			if ok && ip.IsPrivate() && ip.Is4() {
				hasPrivateIP = true
				break
			}
		}
	}

	if !hasPrivateIP {
		return false
	}

	// Now check for the definitive OpenVPN routes
	if hasOpenVPNRoutesDarwin() {
		if envknob.Bool("TS_DEBUG_OPENVPN") {
			fmt.Printf("netmon: confirmed OpenVPN interface: %s (has characteristic routes)\n", nif.Name)
		}
		return true
	}

	return false
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netutil

import (
	"errors"
	"net"
	"net/netip"
)

// DefaultInterfacePortable looks up the current default interface using a portable lookup method that
// works on most systems with a BSD style socket interface.
//
// Returns the interface name and IP address of the default route interface.
//
// If the default cannot be determined, an error is returned.
// Requires that there is a route on the system servicing UDP IPv4.
func DefaultInterfacePortable() (string, netip.Addr, error) {
	// Note: UDP dial just performs a connect(2), and doesn't actually send a packet.
	c, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return "", netip.Addr{}, err
	}
	laddr := c.LocalAddr().(*net.UDPAddr)
	c.Close()

	ifs, err := net.Interfaces()
	if err != nil {
		return "", netip.Addr{}, err
	}

	var (
		iface *net.Interface
		ipnet *net.IPNet
	)
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			return "", netip.Addr{}, err
		}
		for _, addr := range addrs {
			if ipn, ok := addr.(*net.IPNet); ok {
				if ipn.Contains(laddr.IP) {
					if ipnet == nil {
						ipnet = ipn
						iface = &ifc
					} else {
						newSize, _ := ipn.Mask.Size()
						oldSize, _ := ipnet.Mask.Size()
						if newSize > oldSize {
							ipnet = ipn
							iface = &ifc
						}
					}
				}
			}
		}
	}
	if iface == nil {
		return "", netip.Addr{}, errors.New("no default interface")
	}
	return iface.Name, laddr.AddrPort().Addr(), nil
}

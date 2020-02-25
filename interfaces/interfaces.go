// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package interfaces contains helpers for looking up system network interfaces.
package interfaces

import (
	"net"
	"strings"
)

// Tailscale returns the current machine's Tailscale interface, if any.
// If none is found, all zero values are returned.
// A non-nil error is only returned on a problem listing the system interfaces.
func Tailscale() (net.IP, *net.Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, iface := range ifs {
		if !maybeTailscaleInterfaceName(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && IsTailscaleIP(ipnet.IP) {
				return ipnet.IP, &iface, nil
			}
		}
	}
	return nil, nil, nil
}

// HaveIPv6GlobalAddress reports whether the machine appears to have a
// global scope unicast IPv6 address.
//
// It only returns an error if there's a problem querying the system
// interfaces.
func HaveIPv6GlobalAddress() (bool, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return false, err
	}
	for _, iface := range ifs {
		if isLoopbackInterfaceName(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.To4() != nil || !ipnet.IP.IsGlobalUnicast() {
				continue
			}
			return true, nil
		}
	}
	return false, nil
}

func isLoopbackInterfaceName(s string) bool {
	return strings.HasPrefix(s, "lo")
}

// maybeTailscaleInterfaceName reports whether s is an interface
// name that might be used by Tailscale.
func maybeTailscaleInterfaceName(s string) bool {
	return strings.HasPrefix(s, "wg") ||
		strings.HasPrefix(s, "ts") ||
		strings.HasPrefix(s, "tailscale")
}

// IsTailscaleIP reports whether ip is an IP in a range used by
// Tailscale virtual network interfaces.
func IsTailscaleIP(ip net.IP) bool {
	return cgNAT.Contains(ip)
}

var cgNAT = func() *net.IPNet {
	_, ipNet, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		panic(err)
	}
	return ipNet
}()

// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package interfaces contains helpers for looking up system network interfaces.
package interfaces

import (
	"fmt"
	"net"
	"reflect"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/net/tsaddr"
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

// maybeTailscaleInterfaceName reports whether s is an interface
// name that might be used by Tailscale.
func maybeTailscaleInterfaceName(s string) bool {
	return strings.HasPrefix(s, "wg") ||
		strings.HasPrefix(s, "ts") ||
		strings.HasPrefix(s, "tailscale") ||
		strings.HasPrefix(s, "utun")
}

// IsTailscaleIP reports whether ip is an IP in a range used by
// Tailscale virtual network interfaces.
func IsTailscaleIP(ip net.IP) bool {
	nip, _ := netaddr.FromStdIP(ip) // TODO: push this up to caller, change func signature
	return tsaddr.IsTailscaleIP(nip)
}

func isUp(nif *net.Interface) bool       { return nif.Flags&net.FlagUp != 0 }
func isLoopback(nif *net.Interface) bool { return nif.Flags&net.FlagLoopback != 0 }

// LocalAddresses returns the machine's IP addresses, separated by
// whether they're loopback addresses.
func LocalAddresses() (regular, loopback []string, err error) {
	// TODO(crawshaw): don't serve interface addresses that we are routing
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for i := range ifaces {
		iface := &ifaces[i]
		if !isUp(iface) {
			// Down interfaces don't count
			continue
		}
		ifcIsLoopback := isLoopback(iface)

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, nil, err
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				ip, ok := netaddr.FromStdIP(v.IP)
				if !ok {
					continue
				}
				if ip.Is6() {
					// TODO(crawshaw): IPv6 support.
					// Easy to do here, but we need good endpoint ordering logic.
					continue
				}
				// TODO(apenwarr): don't special case cgNAT.
				// In the general wireguard case, it might
				// very well be something we can route to
				// directly, because both nodes are
				// behind the same CGNAT router.
				if tsaddr.IsTailscaleIP(ip) {
					continue
				}
				if linkLocalIPv4.Contains(ip) {
					continue
				}
				if ip.IsLoopback() || ifcIsLoopback {
					loopback = append(loopback, ip.String())
				} else {
					regular = append(regular, ip.String())
				}
			}
		}
	}
	return regular, loopback, nil
}

// Interface is a wrapper around Go's net.Interface with some extra methods.
type Interface struct {
	*net.Interface
}

func (i Interface) IsLoopback() bool { return isLoopback(i.Interface) }
func (i Interface) IsUp() bool       { return isUp(i.Interface) }

// ForeachInterfaceAddress calls fn for each interface's address on the machine.
func ForeachInterfaceAddress(fn func(Interface, netaddr.IP)) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for i := range ifaces {
		iface := &ifaces[i]
		addrs, err := iface.Addrs()
		if err != nil {
			return err
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				if ip, ok := netaddr.FromStdIP(v.IP); ok {
					fn(Interface{iface}, ip)
				}
			}
		}
	}
	return nil
}

// State is intended to store the state of the machine's network interfaces,
// routing table, and other network configuration.
// For now it's pretty basic.
type State struct {
	InterfaceIPs map[string][]netaddr.IP
	InterfaceUp  map[string]bool

	// HaveV6Global is whether this machine has an IPv6 global address
	// on some interface.
	HaveV6Global bool

	// HaveV4 is whether the machine has some non-localhost IPv4 address.
	HaveV4 bool

	// IsExpensive is whether the current network interface is
	// considered "expensive", which currently means LTE/etc
	// instead of Wifi. This field is not populated by GetState.
	IsExpensive bool
}

func (s *State) Equal(s2 *State) bool {
	return reflect.DeepEqual(s, s2)
}

// RemoveTailscaleInterfaces modifes s to remove any interfaces that
// are owned by this process. (TODO: make this true; currently it
// makes the Linux-only assumption that the interface is named
// /^tailscale/)
func (s *State) RemoveTailscaleInterfaces() {
	for name := range s.InterfaceIPs {
		if strings.HasPrefix(name, "tailscale") { // TODO: use --tun flag value, etc; see TODO in method doc
			delete(s.InterfaceIPs, name)
			delete(s.InterfaceUp, name)
		}
	}
}

// GetState returns the state of all the current machine's network interfaces.
//
// It does not set the returned State.IsExpensive. The caller can populate that.
func GetState() (*State, error) {
	s := &State{
		InterfaceIPs: make(map[string][]netaddr.IP),
		InterfaceUp:  make(map[string]bool),
	}
	if err := ForeachInterfaceAddress(func(ni Interface, ip netaddr.IP) {
		s.InterfaceIPs[ni.Name] = append(s.InterfaceIPs[ni.Name], ip)
		s.InterfaceUp[ni.Name] = ni.IsUp()
		s.HaveV6Global = s.HaveV6Global || isGlobalV6(ip)
		s.HaveV4 = s.HaveV4 || (ip.Is4() && !ip.IsLoopback())
	}); err != nil {
		return nil, err
	}
	return s, nil
}

// HTTPOfListener returns the HTTP address to ln.
// If the listener is listening on the unspecified address, it
// it tries to find a reasonable interface address on the machine to use.
func HTTPOfListener(ln net.Listener) string {
	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !ta.IP.IsUnspecified() {
		return fmt.Sprintf("http://%v/", ln.Addr())
	}

	var goodIP string
	var privateIP string
	ForeachInterfaceAddress(func(i Interface, ip netaddr.IP) {
		if isPrivateIP(ip) {
			if privateIP == "" {
				privateIP = ip.String()
			}
			return
		}
		goodIP = ip.String()
	})
	if privateIP != "" {
		goodIP = privateIP
	}
	if goodIP != "" {
		return fmt.Sprintf("http://%v/", net.JoinHostPort(goodIP, fmt.Sprint(ta.Port)))
	}
	return fmt.Sprintf("http://localhost:%v/", fmt.Sprint(ta.Port))

}

var likelyHomeRouterIP func() (netaddr.IP, bool)

// LikelyHomeRouterIP returns the likely IP of the residential router,
// which will always be an IPv4 private address, if found.
// In addition, it returns the IP address of the current machine on
// the LAN using that gateway.
// This is used as the destination for UPnP, NAT-PMP, PCP, etc queries.
func LikelyHomeRouterIP() (gateway, myIP netaddr.IP, ok bool) {
	if likelyHomeRouterIP != nil {
		gateway, ok = likelyHomeRouterIP()
		if !ok {
			return
		}
	}
	if !ok {
		return
	}
	ForeachInterfaceAddress(func(i Interface, ip netaddr.IP) {
		if !i.IsUp() || ip.IsZero() || !myIP.IsZero() {
			return
		}
		for _, prefix := range privatev4s {
			if prefix.Contains(gateway) && prefix.Contains(ip) {
				myIP = ip
				ok = true
				return
			}
		}
	})
	return gateway, myIP, !myIP.IsZero()
}

func isPrivateIP(ip netaddr.IP) bool {
	return private1.Contains(ip) || private2.Contains(ip) || private3.Contains(ip)
}

func isGlobalV6(ip netaddr.IP) bool {
	return v6Global1.Contains(ip)
}

func mustCIDR(s string) netaddr.IPPrefix {
	prefix, err := netaddr.ParseIPPrefix(s)
	if err != nil {
		panic(err)
	}
	return prefix
}

var (
	private1      = mustCIDR("10.0.0.0/8")
	private2      = mustCIDR("172.16.0.0/12")
	private3      = mustCIDR("192.168.0.0/16")
	privatev4s    = []netaddr.IPPrefix{private1, private2, private3}
	linkLocalIPv4 = mustCIDR("169.254.0.0/16")
	v6Global1     = mustCIDR("2000::/3")
)

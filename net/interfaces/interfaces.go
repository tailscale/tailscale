// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package interfaces contains helpers for looking up system network interfaces.
package interfaces

import (
	"fmt"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tshttpproxy"
)

// LoginEndpointForProxyDetermination is the URL used for testing
// which HTTP proxy the system should use.
var LoginEndpointForProxyDetermination = "https://login.tailscale.com/"

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
			if ipnet, ok := a.(*net.IPNet); ok {
				nip, ok := netaddr.FromStdIP(ipnet.IP)
				if ok && tsaddr.IsTailscaleIP(nip) {
					return ipnet.IP, &iface, nil
				}
			}
		}
	}
	return nil, nil, nil
}

// maybeTailscaleInterfaceName reports whether s is an interface
// name that might be used by Tailscale.
func maybeTailscaleInterfaceName(s string) bool {
	return s == "Tailscale" ||
		strings.HasPrefix(s, "wg") ||
		strings.HasPrefix(s, "ts") ||
		strings.HasPrefix(s, "tailscale") ||
		strings.HasPrefix(s, "utun")
}

func isUp(nif *net.Interface) bool       { return nif.Flags&net.FlagUp != 0 }
func isLoopback(nif *net.Interface) bool { return nif.Flags&net.FlagLoopback != 0 }

func isProblematicInterface(nif *net.Interface) bool {
	name := nif.Name
	// Don't try to send disco/etc packets over zerotier; they effectively
	// DoS each other by doing traffic amplification, both of them
	// preferring/trying to use each other for transport. See:
	// https://github.com/tailscale/tailscale/issues/1208
	if strings.HasPrefix(name, "zt") || (runtime.GOOS == "windows" && strings.Contains(name, "ZeroTier")) {
		return true
	}
	return false
}

// LocalAddresses returns the machine's IP addresses, separated by
// whether they're loopback addresses.
func LocalAddresses() (regular, loopback []netaddr.IP, err error) {
	// TODO(crawshaw): don't serve interface addresses that we are routing
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for i := range ifaces {
		iface := &ifaces[i]
		if !isUp(iface) || isProblematicInterface(iface) {
			// Skip down interfaces and ones that are
			// problematic that we don't want to try to
			// send Tailscale traffic over.
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
				// TODO(apenwarr): don't special case cgNAT.
				// In the general wireguard case, it might
				// very well be something we can route to
				// directly, because both nodes are
				// behind the same CGNAT router.
				if tsaddr.IsTailscaleIP(ip) {
					continue
				}
				if ip.IsLinkLocalUnicast() {
					continue
				}
				if ip.IsLoopback() || ifcIsLoopback {
					loopback = append(loopback, ip)
				} else {
					regular = append(regular, ip)
				}
			}
		}
	}
	sortIPs(regular)
	sortIPs(loopback)
	return regular, loopback, nil
}

func sortIPs(s []netaddr.IP) {
	sort.Slice(s, func(i, j int) bool { return s[i].Less(s[j]) })
}

// Interface is a wrapper around Go's net.Interface with some extra methods.
type Interface struct {
	*net.Interface
}

func (i Interface) IsLoopback() bool { return isLoopback(i.Interface) }
func (i Interface) IsUp() bool       { return isUp(i.Interface) }

// ForeachInterfaceAddress calls fn for each interface's address on
// the machine. The IPPrefix's IP is the IP address assigned to the
// interface, and Bits are the subnet mask.
func ForeachInterfaceAddress(fn func(Interface, netaddr.IPPrefix)) error {
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
				if pfx, ok := netaddr.FromStdIPNet(v); ok {
					fn(Interface{iface}, pfx)
				}
			}
		}
	}
	return nil
}

// ForeachInterface calls fn for each interface on the machine, with
// all its addresses. The IPPrefix's IP is the IP address assigned to
// the interface, and Bits are the subnet mask.
func ForeachInterface(fn func(Interface, []netaddr.IPPrefix)) error {
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
		var pfxs []netaddr.IPPrefix
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				if pfx, ok := netaddr.FromStdIPNet(v); ok {
					pfxs = append(pfxs, pfx)
				}
			}
		}
		fn(Interface{iface}, pfxs)
	}
	return nil
}

// State is intended to store the state of the machine's network interfaces,
// routing table, and other network configuration.
// For now it's pretty basic.
type State struct {
	// InterfaceIPs maps from an interface name to the IP addresses
	// configured on that interface. Each address is represented as an
	// IPPrefix, where the IP is the interface IP address and Bits is
	// the subnet mask.
	InterfaceIPs map[string][]netaddr.IPPrefix
	Interface    map[string]Interface

	// HaveV6Global is whether this machine has an IPv6 global address
	// on some non-Tailscale interface that's up.
	HaveV6Global bool

	// HaveV4 is whether the machine has some non-localhost,
	// non-link-local IPv4 address on a non-Tailscale interface that's up.
	HaveV4 bool

	// IsExpensive is whether the current network interface is
	// considered "expensive", which currently means LTE/etc
	// instead of Wifi. This field is not populated by GetState.
	IsExpensive bool

	// DefaultRouteInterface is the interface name for the machine's default route.
	// It is not yet populated on all OSes.
	// Its exact value should not be assumed to be a map key for
	// the Interface maps above; it's only used for debugging.
	DefaultRouteInterface string

	// HTTPProxy is the HTTP proxy to use.
	HTTPProxy string

	// PAC is the URL to the Proxy Autoconfig URL, if applicable.
	PAC string
}

func (s *State) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "interfaces.State{defaultRoute=%v ifs={", s.DefaultRouteInterface)
	ifs := make([]string, 0, len(s.Interface))
	for k := range s.Interface {
		if anyInterestingIP(s.InterfaceIPs[k]) {
			ifs = append(ifs, k)
		}
	}
	sort.Slice(ifs, func(i, j int) bool {
		upi, upj := s.Interface[ifs[i]].IsUp(), s.Interface[ifs[j]].IsUp()
		if upi != upj {
			// Up sorts before down.
			return upi
		}
		return ifs[i] < ifs[j]
	})
	for i, ifName := range ifs {
		if i > 0 {
			sb.WriteString(" ")
		}
		if s.Interface[ifName].IsUp() {
			fmt.Fprintf(&sb, "%s:[", ifName)
			needSpace := false
			for _, pfx := range s.InterfaceIPs[ifName] {
				if !isInterestingIP(pfx.IP) {
					continue
				}
				if needSpace {
					sb.WriteString(" ")
				}
				fmt.Fprintf(&sb, "%s", pfx)
				needSpace = true
			}
			sb.WriteString("]")
		} else {
			fmt.Fprintf(&sb, "%s:down", ifName)
		}
	}
	sb.WriteString("}")

	if s.IsExpensive {
		sb.WriteString(" expensive")
	}
	if s.HTTPProxy != "" {
		fmt.Fprintf(&sb, " httpproxy=%s", s.HTTPProxy)
	}
	if s.PAC != "" {
		fmt.Fprintf(&sb, " pac=%s", s.PAC)
	}
	fmt.Fprintf(&sb, " v4=%v v6global=%v}", s.HaveV4, s.HaveV6Global)
	return sb.String()
}

func (s *State) Equal(s2 *State) bool {
	return reflect.DeepEqual(s, s2)
}

func (s *State) HasPAC() bool { return s != nil && s.PAC != "" }

// AnyInterfaceUp reports whether any interface seems like it has Internet access.
func (s *State) AnyInterfaceUp() bool {
	return s != nil && (s.HaveV4 || s.HaveV6Global)
}

// RemoveUninterestingInterfacesAndAddresses removes uninteresting IPs
// from InterfaceIPs, also removing from both the InterfaceIPs and
// InterfaceUp map any interfaces that don't have any interesting IPs.
func (s *State) RemoveUninterestingInterfacesAndAddresses() {
	for ifName := range s.Interface {
		ips := s.InterfaceIPs[ifName]
		keep := ips[:0]
		for _, pfx := range ips {
			if isInterestingIP(pfx.IP) {
				keep = append(keep, pfx)
			}
		}
		if len(keep) == 0 {
			delete(s.Interface, ifName)
			delete(s.InterfaceIPs, ifName)
			continue
		}
		if len(keep) < len(ips) {
			s.InterfaceIPs[ifName] = keep
		}
	}
}

// RemoveTailscaleInterfaces modifes s to remove any interfaces that
// are owned by this process. (TODO: make this true; currently it
// uses some heuristics)
func (s *State) RemoveTailscaleInterfaces() {
	for name, pfxs := range s.InterfaceIPs {
		if isTailscaleInterface(name, pfxs) {
			delete(s.InterfaceIPs, name)
			delete(s.Interface, name)
		}
	}
}

func hasTailscaleIP(pfxs []netaddr.IPPrefix) bool {
	for _, pfx := range pfxs {
		if tsaddr.IsTailscaleIP(pfx.IP) {
			return true
		}
	}
	return false
}

func isTailscaleInterface(name string, ips []netaddr.IPPrefix) bool {
	if runtime.GOOS == "darwin" && strings.HasPrefix(name, "utun") && hasTailscaleIP(ips) {
		// On macOS in the sandboxed app (at least as of
		// 2021-02-25), we often see two utun devices
		// (e.g. utun4 and utun7) with the same IPv4 and IPv6
		// addresses. Just remove all utun devices with
		// Tailscale IPs until we know what's happening with
		// macOS NetworkExtensions and utun devices.
		return true
	}
	return name == "Tailscale" || // as it is on Windows
		strings.HasPrefix(name, "tailscale") // TODO: use --tun flag value, etc; see TODO in method doc
}

// getPAC, if non-nil, returns the current PAC file URL.
var getPAC func() string

// GetState returns the state of all the current machine's network interfaces.
//
// It does not set the returned State.IsExpensive. The caller can populate that.
func GetState() (*State, error) {
	s := &State{
		InterfaceIPs: make(map[string][]netaddr.IPPrefix),
		Interface:    make(map[string]Interface),
	}
	if err := ForeachInterface(func(ni Interface, pfxs []netaddr.IPPrefix) {
		ifUp := ni.IsUp()
		s.Interface[ni.Name] = ni
		s.InterfaceIPs[ni.Name] = append(s.InterfaceIPs[ni.Name], pfxs...)
		if !ifUp || isTailscaleInterface(ni.Name, pfxs) {
			return
		}
		for _, pfx := range pfxs {
			if pfx.IP.IsLoopback() || pfx.IP.IsLinkLocalUnicast() {
				continue
			}
			s.HaveV6Global = s.HaveV6Global || isGlobalV6(pfx.IP)
			s.HaveV4 = s.HaveV4 || pfx.IP.Is4()
		}
	}); err != nil {
		return nil, err
	}

	s.DefaultRouteInterface, _ = DefaultRouteInterface()

	if s.AnyInterfaceUp() {
		req, err := http.NewRequest("GET", LoginEndpointForProxyDetermination, nil)
		if err != nil {
			return nil, err
		}
		if u, err := tshttpproxy.ProxyFromEnvironment(req); err == nil && u != nil {
			s.HTTPProxy = u.String()
		}
		if getPAC != nil {
			s.PAC = getPAC()
		}
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
	ForeachInterfaceAddress(func(i Interface, pfx netaddr.IPPrefix) {
		ip := pfx.IP
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
	ForeachInterfaceAddress(func(i Interface, pfx netaddr.IPPrefix) {
		ip := pfx.IP
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
	private1   = mustCIDR("10.0.0.0/8")
	private2   = mustCIDR("172.16.0.0/12")
	private3   = mustCIDR("192.168.0.0/16")
	privatev4s = []netaddr.IPPrefix{private1, private2, private3}
	v6Global1  = mustCIDR("2000::/3")
)

// anyInterestingIP reports whether pfxs contains any IP that matches
// isInterestingIP.
func anyInterestingIP(pfxs []netaddr.IPPrefix) bool {
	for _, pfx := range pfxs {
		if isInterestingIP(pfx.IP) {
			return true
		}
	}
	return false
}

// isInterestingIP reports whether ip is an interesting IP that we
// should log in interfaces.State logging. We don't need to show
// localhost or link-local addresses.
func isInterestingIP(ip netaddr.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}

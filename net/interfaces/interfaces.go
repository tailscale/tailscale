// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package interfaces contains helpers for looking up system network interfaces.
package interfaces

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/hostinfo"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tshttpproxy"
)

// LoginEndpointForProxyDetermination is the URL used for testing
// which HTTP proxy the system should use.
var LoginEndpointForProxyDetermination = "https://controlplane.tailscale.com/"

// Tailscale returns the current machine's Tailscale interface, if any.
// If none is found, all zero values are returned.
// A non-nil error is only returned on a problem listing the system interfaces.
func Tailscale() ([]netaddr.IP, *net.Interface, error) {
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
		var tsIPs []netaddr.IP
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				nip, ok := netaddr.FromStdIP(ipnet.IP)
				if ok && tsaddr.IsTailscaleIP(nip) {
					tsIPs = append(tsIPs, nip)
				}
			}
		}
		if len(tsIPs) > 0 {
			return tsIPs, &iface, nil
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
// whether they're loopback addresses. If there are no regular addresses
// it will return any IPv4 linklocal or IPv6 unique local addresses because we
// know of environments where these are used with NAT to provide connectivity.
func LocalAddresses() (regular, loopback []netaddr.IP, err error) {
	// TODO(crawshaw): don't serve interface addresses that we are routing
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	var regular4, regular6, linklocal4, ula6 []netaddr.IP
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
				if ip.IsLoopback() || ifcIsLoopback {
					loopback = append(loopback, ip)
				} else if ip.IsLinkLocalUnicast() {
					if ip.Is4() {
						linklocal4 = append(linklocal4, ip)
					}

					// We know of no cases where the IPv6 fe80:: addresses
					// are used to provide WAN connectivity. It is also very
					// common for users to have no IPv6 WAN connectivity,
					// but their OS supports IPv6 so they have an fe80::
					// address. We don't want to report all of those
					// IPv6 LL to Control.
				} else if ip.Is6() && ip.IsPrivate() {
					// Google Cloud Run uses NAT with IPv6 Unique
					// Local Addresses to provide IPv6 connectivity.
					ula6 = append(ula6, ip)
				} else {
					if ip.Is4() {
						regular4 = append(regular4, ip)
					} else {
						regular6 = append(regular6, ip)
					}
				}
			}
		}
	}
	if len(regular4) == 0 && len(regular6) == 0 {
		// if we have no usable IP addresses then be willing to accept
		// addresses we otherwise wouldn't, like:
		//   + 169.254.x.x (AWS Lambda uses NAT with these)
		//   + IPv6 ULA (Google Cloud Run uses these with address translation)
		if hostinfo.GetEnvType() == hostinfo.AWSLambda {
			regular4 = linklocal4
		}
		regular6 = ula6
	}
	regular = append(regular4, regular6...)
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
		sort.Slice(pfxs, func(i, j int) bool {
			return pfxs[i].IP().Less(pfxs[j].IP())
		})
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

	// HaveV6 is whether this machine has an IPv6 Global or Unique Local Address
	// which might provide connectivity on a non-Tailscale interface that's up.
	HaveV6 bool

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
				if !isInterestingIP(pfx.IP()) {
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
	fmt.Fprintf(&sb, " v4=%v v6=%v}", s.HaveV4, s.HaveV6)
	return sb.String()
}

// EqualFiltered reports whether s and s2 are equal,
// considering only interfaces in s for which filter returns true.
func (s *State) EqualFiltered(s2 *State, filter func(i Interface, ips []netaddr.IPPrefix) bool) bool {
	if s == nil && s2 == nil {
		return true
	}
	if s == nil || s2 == nil {
		return false
	}
	if s.HaveV6 != s2.HaveV6 ||
		s.HaveV4 != s2.HaveV4 ||
		s.IsExpensive != s2.IsExpensive ||
		s.DefaultRouteInterface != s2.DefaultRouteInterface ||
		s.HTTPProxy != s2.HTTPProxy ||
		s.PAC != s2.PAC {
		return false
	}
	for iname, i := range s.Interface {
		ips := s.InterfaceIPs[iname]
		if !filter(i, ips) {
			continue
		}
		i2, ok := s2.Interface[iname]
		if !ok {
			return false
		}
		ips2, ok := s2.InterfaceIPs[iname]
		if !ok {
			return false
		}
		if !interfacesEqual(i, i2) || !prefixesEqual(ips, ips2) {
			return false
		}
	}
	return true
}

func interfacesEqual(a, b Interface) bool {
	return a.Index == b.Index &&
		a.MTU == b.MTU &&
		a.Name == b.Name &&
		a.Flags == b.Flags &&
		bytes.Equal([]byte(a.HardwareAddr), []byte(b.HardwareAddr))
}

func prefixesEqual(a, b []netaddr.IPPrefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

// FilterInteresting reports whether i is an interesting non-Tailscale interface.
func FilterInteresting(i Interface, ips []netaddr.IPPrefix) bool {
	return !isTailscaleInterface(i.Name, ips) && anyInterestingIP(ips)
}

// FilterAll always returns true, to use EqualFiltered against all interfaces.
func FilterAll(i Interface, ips []netaddr.IPPrefix) bool { return true }

func (s *State) HasPAC() bool { return s != nil && s.PAC != "" }

// AnyInterfaceUp reports whether any interface seems like it has Internet access.
func (s *State) AnyInterfaceUp() bool {
	return s != nil && (s.HaveV4 || s.HaveV6)
}

func hasTailscaleIP(pfxs []netaddr.IPPrefix) bool {
	for _, pfx := range pfxs {
		if tsaddr.IsTailscaleIP(pfx.IP()) {
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
			if pfx.IP().IsLoopback() {
				continue
			}
			s.HaveV6 = s.HaveV6 || isUsableV6(pfx.IP())
			s.HaveV4 = s.HaveV4 || isUsableV4(pfx.IP())
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
		ip := pfx.IP()
		if ip.IsPrivate() {
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
		ip := pfx.IP()
		if !i.IsUp() || ip.IsZero() || !myIP.IsZero() {
			return
		}
		if gateway.IsPrivate() && ip.IsPrivate() {
			myIP = ip
			ok = true
			return
		}
	})
	return gateway, myIP, !myIP.IsZero()
}

// isUsableV4 reports whether ip is a usable IPv4 address which could
// conceivably be used to get Internet connectivity. Globally routable and
// private IPv4 addresses are always Usable, and link local 169.254.x.x
// addresses are in some environments.
func isUsableV4(ip netaddr.IP) bool {
	if !ip.Is4() || ip.IsLoopback() {
		return false
	}
	if ip.IsLinkLocalUnicast() {
		return hostinfo.GetEnvType() == hostinfo.AWSLambda
	}
	return true
}

// isUsableV6 reports whether ip is a usable IPv6 address which could
// conceivably be used to get Internet connectivity. Globally routable
// IPv6 addresses are always Usable, and Unique Local Addresses
// (fc00::/7) are in some environments used with address translation.
func isUsableV6(ip netaddr.IP) bool {
	return v6Global1.Contains(ip) ||
		(ip.Is6() && ip.IsPrivate() && !tsaddr.TailscaleULARange().Contains(ip))
}

var (
	v6Global1 = netaddr.MustParseIPPrefix("2000::/3")
)

// anyInterestingIP reports whether pfxs contains any IP that matches
// isInterestingIP.
func anyInterestingIP(pfxs []netaddr.IPPrefix) bool {
	for _, pfx := range pfxs {
		if isInterestingIP(pfx.IP()) {
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

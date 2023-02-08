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
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"

	"tailscale.com/hostinfo"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tshttpproxy"
)

// LoginEndpointForProxyDetermination is the URL used for testing
// which HTTP proxy the system should use.
var LoginEndpointForProxyDetermination = "https://controlplane.tailscale.com/"

// Tailscale returns the current machine's Tailscale interface, if any.
// If none is found, all zero values are returned.
// A non-nil error is only returned on a problem listing the system interfaces.
func Tailscale() ([]netip.Addr, *net.Interface, error) {
	ifs, err := netInterfaces()
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
		var tsIPs []netip.Addr
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				nip, ok := netip.AddrFromSlice(ipnet.IP)
				nip = nip.Unmap()
				if ok && tsaddr.IsTailscaleIP(nip) {
					tsIPs = append(tsIPs, nip)
				}
			}
		}
		if len(tsIPs) > 0 {
			return tsIPs, iface.Interface, nil
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
func LocalAddresses() (regular, loopback []netip.Addr, err error) {
	// TODO(crawshaw): don't serve interface addresses that we are routing
	ifaces, err := netInterfaces()
	if err != nil {
		return nil, nil, err
	}
	var regular4, regular6, linklocal4, ula6 []netip.Addr
	for _, iface := range ifaces {
		stdIf := iface.Interface
		if !isUp(stdIf) || isProblematicInterface(stdIf) {
			// Skip down interfaces and ones that are
			// problematic that we don't want to try to
			// send Tailscale traffic over.
			continue
		}
		ifcIsLoopback := isLoopback(stdIf)

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, nil, err
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				ip, ok := netip.AddrFromSlice(v.IP)
				if !ok {
					continue
				}
				ip = ip.Unmap()
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

func sortIPs(s []netip.Addr) {
	sort.Slice(s, func(i, j int) bool { return s[i].Less(s[j]) })
}

// Interface is a wrapper around Go's net.Interface with some extra methods.
type Interface struct {
	*net.Interface
	AltAddrs []net.Addr // if non-nil, returned by Addrs
	Desc     string     // extra description (used on Windows)
}

func (i Interface) IsLoopback() bool { return isLoopback(i.Interface) }
func (i Interface) IsUp() bool       { return isUp(i.Interface) }
func (i Interface) Addrs() ([]net.Addr, error) {
	if i.AltAddrs != nil {
		return i.AltAddrs, nil
	}
	return i.Interface.Addrs()
}

// ForeachInterfaceAddress is a wrapper for GetList, then
// List.ForeachInterfaceAddress.
func ForeachInterfaceAddress(fn func(Interface, netip.Prefix)) error {
	ifaces, err := GetList()
	if err != nil {
		return err
	}
	return ifaces.ForeachInterfaceAddress(fn)
}

// ForeachInterfaceAddress calls fn for each interface in ifaces, with
// all its addresses. The IPPrefix's IP is the IP address assigned to
// the interface, and Bits are the subnet mask.
func (ifaces List) ForeachInterfaceAddress(fn func(Interface, netip.Prefix)) error {
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return err
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				if pfx, ok := netaddr.FromStdIPNet(v); ok {
					fn(iface, pfx)
				}
			}
		}
	}
	return nil
}

// ForeachInterface is a wrapper for GetList, then
// List.ForeachInterface.
func ForeachInterface(fn func(Interface, []netip.Prefix)) error {
	ifaces, err := GetList()
	if err != nil {
		return err
	}
	return ifaces.ForeachInterface(fn)
}

// ForeachInterface calls fn for each interface in ifaces, with
// all its addresses. The IPPrefix's IP is the IP address assigned to
// the interface, and Bits are the subnet mask.
func (ifaces List) ForeachInterface(fn func(Interface, []netip.Prefix)) error {
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return err
		}
		var pfxs []netip.Prefix
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				if pfx, ok := netaddr.FromStdIPNet(v); ok {
					pfxs = append(pfxs, pfx)
				}
			}
		}
		sort.Slice(pfxs, func(i, j int) bool {
			return pfxs[i].Addr().Less(pfxs[j].Addr())
		})
		fn(iface, pfxs)
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
	InterfaceIPs map[string][]netip.Prefix
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

	// DefaultRouteInterface is the interface name for the
	// machine's default route.
	//
	// It is not yet populated on all OSes.
	//
	// When non-empty, its value is the map key into Interface and
	// InterfaceIPs.
	DefaultRouteInterface string

	// HTTPProxy is the HTTP proxy to use, if any.
	HTTPProxy string

	// PAC is the URL to the Proxy Autoconfig URL, if applicable.
	PAC string
}

func (s *State) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "interfaces.State{defaultRoute=%v ", s.DefaultRouteInterface)
	if s.DefaultRouteInterface != "" {
		if iface, ok := s.Interface[s.DefaultRouteInterface]; ok && iface.Desc != "" {
			fmt.Fprintf(&sb, "(%s) ", iface.Desc)
		}
	}
	sb.WriteString("ifs={")
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
				if !isInterestingIP(pfx.Addr()) {
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

// An InterfaceFilter indicates whether EqualFiltered should use i when deciding whether two States are equal.
// ips are all the IPPrefixes associated with i.
type InterfaceFilter func(i Interface, ips []netip.Prefix) bool

// An IPFilter indicates whether EqualFiltered should use ip when deciding whether two States are equal.
// ip is an ip address associated with some interface under consideration.
type IPFilter func(ip netip.Addr) bool

// EqualFiltered reports whether s and s2 are equal,
// considering only interfaces in s for which filter returns true,
// and considering only IPs for those interfaces for which filterIP returns true.
func (s *State) EqualFiltered(s2 *State, useInterface InterfaceFilter, useIP IPFilter) bool {
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
		if !useInterface(i, ips) {
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
		if !interfacesEqual(i, i2) || !prefixesEqualFiltered(ips, ips2, useIP) {
			return false
		}
	}
	return true
}

// HasIP reports whether any interface has the provided IP address.
func (s *State) HasIP(ip netip.Addr) bool {
	if s == nil {
		return false
	}
	want := netip.PrefixFrom(ip, ip.BitLen())
	for _, pv := range s.InterfaceIPs {
		for _, p := range pv {
			if p == want {
				return true
			}
		}
	}
	return false
}

func interfacesEqual(a, b Interface) bool {
	return a.Index == b.Index &&
		a.MTU == b.MTU &&
		a.Name == b.Name &&
		a.Flags == b.Flags &&
		bytes.Equal([]byte(a.HardwareAddr), []byte(b.HardwareAddr))
}

func filteredIPPs(ipps []netip.Prefix, useIP IPFilter) []netip.Prefix {
	// TODO: rewrite prefixesEqualFiltered to avoid making copies
	x := make([]netip.Prefix, 0, len(ipps))
	for _, ipp := range ipps {
		if useIP(ipp.Addr()) {
			x = append(x, ipp)
		}
	}
	return x
}

func prefixesEqualFiltered(a, b []netip.Prefix, useIP IPFilter) bool {
	return prefixesEqual(filteredIPPs(a, useIP), filteredIPPs(b, useIP))
}

func prefixesEqual(a, b []netip.Prefix) bool {
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

// UseInterestingInterfaces is an InterfaceFilter that reports whether i is an interesting interface.
// An interesting interface if it is (a) not owned by Tailscale and (b) routes interesting IP addresses.
// See UseInterestingIPs for the definition of an interesting IP address.
func UseInterestingInterfaces(i Interface, ips []netip.Prefix) bool {
	return !isTailscaleInterface(i.Name, ips) && anyInterestingIP(ips)
}

// UseInterestingIPs is an IPFilter that reports whether ip is an interesting IP address.
// An IP address is interesting if it is neither a loopback nor a link local unicast IP address.
func UseInterestingIPs(ip netip.Addr) bool {
	return isInterestingIP(ip)
}

// UseAllInterfaces is an InterfaceFilter that includes all interfaces.
func UseAllInterfaces(i Interface, ips []netip.Prefix) bool { return true }

// UseAllIPs is an IPFilter that includes all IPs.
func UseAllIPs(ips netip.Addr) bool { return true }

func (s *State) HasPAC() bool { return s != nil && s.PAC != "" }

// AnyInterfaceUp reports whether any interface seems like it has Internet access.
func (s *State) AnyInterfaceUp() bool {
	if runtime.GOOS == "js" {
		return true
	}
	return s != nil && (s.HaveV4 || s.HaveV6)
}

func hasTailscaleIP(pfxs []netip.Prefix) bool {
	for _, pfx := range pfxs {
		if tsaddr.IsTailscaleIP(pfx.Addr()) {
			return true
		}
	}
	return false
}

func isTailscaleInterface(name string, ips []netip.Prefix) bool {
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
		InterfaceIPs: make(map[string][]netip.Prefix),
		Interface:    make(map[string]Interface),
	}
	if err := ForeachInterface(func(ni Interface, pfxs []netip.Prefix) {
		ifUp := ni.IsUp()
		s.Interface[ni.Name] = ni
		s.InterfaceIPs[ni.Name] = append(s.InterfaceIPs[ni.Name], pfxs...)
		if !ifUp || isTailscaleInterface(ni.Name, pfxs) {
			return
		}
		for _, pfx := range pfxs {
			if pfx.Addr().IsLoopback() {
				continue
			}
			s.HaveV6 = s.HaveV6 || isUsableV6(pfx.Addr())
			s.HaveV4 = s.HaveV4 || isUsableV4(pfx.Addr())
		}
	}); err != nil {
		return nil, err
	}

	dr, _ := DefaultRoute()
	s.DefaultRouteInterface = dr.InterfaceName

	// Populate description (for Windows, primarily) if present.
	if desc := dr.InterfaceDesc; desc != "" {
		if iface, ok := s.Interface[dr.InterfaceName]; ok {
			iface.Desc = desc
			s.Interface[dr.InterfaceName] = iface
		}
	}

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
	ForeachInterfaceAddress(func(i Interface, pfx netip.Prefix) {
		ip := pfx.Addr()
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

var likelyHomeRouterIP func() (netip.Addr, bool)

// LikelyHomeRouterIP returns the likely IP of the residential router,
// which will always be an IPv4 private address, if found.
// In addition, it returns the IP address of the current machine on
// the LAN using that gateway.
// This is used as the destination for UPnP, NAT-PMP, PCP, etc queries.
func LikelyHomeRouterIP() (gateway, myIP netip.Addr, ok bool) {
	if likelyHomeRouterIP != nil {
		gateway, ok = likelyHomeRouterIP()
		if !ok {
			return
		}
	}
	if !ok {
		return
	}
	ForeachInterfaceAddress(func(i Interface, pfx netip.Prefix) {
		ip := pfx.Addr()
		if !i.IsUp() || !ip.IsValid() || myIP.IsValid() {
			return
		}
		if gateway.IsPrivate() && ip.IsPrivate() {
			myIP = ip
			ok = true
			return
		}
	})
	return gateway, myIP, myIP.IsValid()
}

// isUsableV4 reports whether ip is a usable IPv4 address which could
// conceivably be used to get Internet connectivity. Globally routable and
// private IPv4 addresses are always Usable, and link local 169.254.x.x
// addresses are in some environments.
func isUsableV4(ip netip.Addr) bool {
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
func isUsableV6(ip netip.Addr) bool {
	return v6Global1.Contains(ip) ||
		(ip.Is6() && ip.IsPrivate() && !tsaddr.TailscaleULARange().Contains(ip))
}

var (
	v6Global1 = netip.MustParsePrefix("2000::/3")
)

// anyInterestingIP reports whether pfxs contains any IP that matches
// isInterestingIP.
func anyInterestingIP(pfxs []netip.Prefix) bool {
	for _, pfx := range pfxs {
		if isInterestingIP(pfx.Addr()) {
			return true
		}
	}
	return false
}

// isInterestingIP reports whether ip is an interesting IP that we
// should log in interfaces.State logging. We don't need to show
// localhost or link-local addresses.
func isInterestingIP(ip netip.Addr) bool {
	return !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

var altNetInterfaces func() ([]Interface, error)

// RegisterInterfaceGetter sets the function that's used to query
// the system network interfaces.
func RegisterInterfaceGetter(getInterfaces func() ([]Interface, error)) {
	altNetInterfaces = getInterfaces
}

// List is a list of interfaces on the machine.
type List []Interface

// GetList returns the list of interfaces on the machine.
func GetList() (List, error) {
	return netInterfaces()
}

// netInterfaces is a wrapper around the standard library's net.Interfaces
// that returns a []*Interface instead of a []net.Interface.
// It exists because Android SDK 30 no longer permits Go's net.Interfaces
// to work (Issue 2293); this wrapper lets us the Android app register
// an alternate implementation.
func netInterfaces() ([]Interface, error) {
	if altNetInterfaces != nil {
		return altNetInterfaces()
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ret := make([]Interface, len(ifs))
	for i := range ifs {
		ret[i].Interface = &ifs[i]
	}
	return ret, nil
}

// DefaultRouteDetails are the details about a default route returned
// by DefaultRoute.
type DefaultRouteDetails struct {
	// InterfaceName is the interface name. It must always be populated.
	// It's like "eth0" (Linux), "Ethernet 2" (Windows), "en0" (macOS).
	InterfaceName string

	// InterfaceDesc is populated on Windows at least. It's a
	// longer description, like "Red Hat VirtIO Ethernet Adapter".
	InterfaceDesc string

	// InterfaceIndex is like net.Interface.Index.
	// Zero means not populated.
	InterfaceIndex int

	// TODO(bradfitz): break this out into v4-vs-v6 once that need arises.
}

// DefaultRouteInterface is like DefaultRoute but only returns the
// interface name.
func DefaultRouteInterface() (string, error) {
	dr, err := DefaultRoute()
	if err != nil {
		return "", err
	}
	return dr.InterfaceName, nil
}

// DefaultRoute returns details of the network interface that owns
// the default route, not including any tailscale interfaces.
func DefaultRoute() (DefaultRouteDetails, error) {
	return defaultRoute()
}

// HasCGNATInterface reports whether there are any non-Tailscale interfaces that
// use a CGNAT IP range.
func HasCGNATInterface() (bool, error) {
	hasCGNATInterface := false
	cgnatRange := tsaddr.CGNATRange()
	err := ForeachInterface(func(i Interface, pfxs []netip.Prefix) {
		if hasCGNATInterface || !i.IsUp() || isTailscaleInterface(i.Name, pfxs) {
			return
		}
		for _, pfx := range pfxs {
			if cgnatRange.Overlaps(pfx) {
				hasCGNATInterface = true
				break
			}
		}
	})
	if err != nil {
		return false, err
	}
	return hasCGNATInterface, nil
}

var disableAlternateDefaultRouteInterface atomic.Bool

// SetDisableAlternateDefaultRouteInterface disables the optional external/
// alternate mechanism for getting the default route network interface.
//
// Currently, this only changes the behaviour on BSD-like sytems (FreeBSD and
// Darwin).
func SetDisableAlternateDefaultRouteInterface(v bool) {
	disableAlternateDefaultRouteInterface.Store(v)
}

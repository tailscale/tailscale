// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package interfaces contains helpers for looking up system network interfaces.
package interfaces

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"slices"
	"sort"
	"strings"

	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tshttpproxy"
)

// LoginEndpointForProxyDetermination is the URL used for testing
// which HTTP proxy the system should use.
var LoginEndpointForProxyDetermination = "https://controlplane.tailscale.com/"

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
		//   + 169.254.x.x (AWS Lambda and Azure App Services use NAT with these)
		//   + IPv6 ULA (Google Cloud Run uses these with address translation)
		regular4 = linklocal4
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
	var ifs []string
	for k := range s.Interface {
		if s.keepInterfaceInStringSummary(k) {
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
		iface := s.Interface[ifName]
		if iface.Interface == nil {
			fmt.Fprintf(&sb, "%s:nil", ifName)
			continue
		}
		if !iface.IsUp() {
			fmt.Fprintf(&sb, "%s:down", ifName)
			continue
		}
		fmt.Fprintf(&sb, "%s:[", ifName)
		needSpace := false
		for _, pfx := range s.InterfaceIPs[ifName] {
			a := pfx.Addr()
			if a.IsMulticast() {
				continue
			}
			fam := "4"
			if a.Is6() {
				fam = "6"
			}
			if needSpace {
				sb.WriteString(" ")
			}
			needSpace = true
			switch {
			case a.IsLoopback():
				fmt.Fprintf(&sb, "lo%s", fam)
			case a.IsLinkLocalUnicast():
				fmt.Fprintf(&sb, "llu%s", fam)
			default:
				fmt.Fprintf(&sb, "%s", pfx)
			}
		}
		sb.WriteString("]")
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

// Equal reports whether s and s2 are exactly equal.
func (s *State) Equal(s2 *State) bool {
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
		i2, ok := s2.Interface[iname]
		if !ok {
			return false
		}
		if !i.Equal(i2) {
			return false
		}
	}
	for iname, vv := range s.InterfaceIPs {
		if !slices.Equal(vv, s2.InterfaceIPs[iname]) {
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
	for _, pv := range s.InterfaceIPs {
		for _, p := range pv {
			if p.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (a Interface) Equal(b Interface) bool {
	if (a.Interface == nil) != (b.Interface == nil) {
		return false
	}
	if !(a.Desc == b.Desc && netAddrsEqual(a.AltAddrs, b.AltAddrs)) {
		return false
	}
	if a.Interface != nil && !(a.Index == b.Index &&
		a.MTU == b.MTU &&
		a.Name == b.Name &&
		a.Flags == b.Flags &&
		bytes.Equal([]byte(a.HardwareAddr), []byte(b.HardwareAddr))) {
		return false
	}
	return true
}

func (s *State) HasPAC() bool { return s != nil && s.PAC != "" }

// AnyInterfaceUp reports whether any interface seems like it has Internet access.
func (s *State) AnyInterfaceUp() bool {
	if runtime.GOOS == "js" || runtime.GOOS == "tamago" {
		return true
	}
	return s != nil && (s.HaveV4 || s.HaveV6)
}

func netAddrsEqual(a, b []net.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i, av := range a {
		if av.Network() != b[i].Network() || av.String() != b[i].String() {
			return false
		}
	}
	return true
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
//
// Deprecated: use netmon.Monitor.InterfaceState instead.
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

// likelyHomeRouterIP, if present, is a platform-specific function that is used
// to determine the likely home router IP of the current system. The signature
// of this function is:
//
//	func() (homeRouter, localAddr netip.Addr, ok bool)
//
// It should return a homeRouter IP and ok=true, or no homeRouter IP and
// ok=false. Optionally, an implementation can return the "self" IP address as
// well, which will be used instead of attempting to determine it by reading
// the system's interfaces.
var likelyHomeRouterIP func() (netip.Addr, netip.Addr, bool)

// For debugging the new behaviour where likelyHomeRouterIP can return the
// "self" IP; should remove after we're confidant this won't cause issues.
var disableLikelyHomeRouterIPSelf = envknob.RegisterBool("TS_DEBUG_DISABLE_LIKELY_HOME_ROUTER_IP_SELF")

// LikelyHomeRouterIP returns the likely IP of the residential router,
// which will always be an IPv4 private address, if found.
// In addition, it returns the IP address of the current machine on
// the LAN using that gateway.
// This is used as the destination for UPnP, NAT-PMP, PCP, etc queries.
func LikelyHomeRouterIP() (gateway, myIP netip.Addr, ok bool) {
	// If we don't have a way to get the home router IP, then we can't do
	// anything; just return.
	if likelyHomeRouterIP == nil {
		return
	}

	// Get the gateway next; if that fails, we can't continue.
	gateway, myIP, ok = likelyHomeRouterIP()
	if !ok {
		return
	}

	// If the platform-specific implementation returned a valid myIP, then
	// we can return it as-is without needing to iterate through all
	// interface addresses.
	if disableLikelyHomeRouterIPSelf() {
		myIP = netip.Addr{}
	}
	if myIP.IsValid() {
		return
	}

	// The platform-specific implementation didn't return a valid myIP;
	// iterate through all interfaces and try to find the correct one.
	ForeachInterfaceAddress(func(i Interface, pfx netip.Prefix) {
		if !i.IsUp() {
			// Skip interfaces that aren't up.
			return
		} else if myIP.IsValid() {
			// We already have a valid self IP; skip this one.
			return
		}

		ip := pfx.Addr()
		if !ip.IsValid() || !ip.Is4() {
			// Skip IPs that aren't valid or aren't IPv4, since we
			// always return an IPv4 address.
			return
		}

		// If this prefix ("interface") doesn't contain the gateway,
		// then we skip it; this can happen if we have multiple valid
		// interfaces and the interface with the route to the internet
		// is ordered after another valid+running interface.
		if !pfx.Contains(gateway) {
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
		switch hostinfo.GetEnvType() {
		case hostinfo.AWSLambda:
			return true
		case hostinfo.AzureAppService:
			return true
		default:
			return false
		}
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

// keepInterfaceInStringSummary reports whether the named interface should be included
// in the String method's summary string.
func (s *State) keepInterfaceInStringSummary(ifName string) bool {
	iface, ok := s.Interface[ifName]
	if !ok || iface.Interface == nil {
		return false
	}
	if ifName == s.DefaultRouteInterface {
		return true
	}
	up := iface.IsUp()
	for _, p := range s.InterfaceIPs[ifName] {
		a := p.Addr()
		if a.IsLinkLocalUnicast() || a.IsLoopback() {
			continue
		}
		if up || a.IsGlobalUnicast() || a.IsPrivate() {
			return true
		}
	}
	return false
}

// isInterestingIP reports whether ip is an interesting IP that we
// should log in interfaces.State logging. We don't need to show
// loopback, link-local addresses, or non-Tailscale ULA addresses.
func isInterestingIP(ip netip.Addr) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	return true
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

var interfaceDebugExtras func(ifIndex int) (string, error)

// InterfaceDebugExtras returns extra debugging information about an interface
// if any (an empty string will be returned if there are no additional details).
// Formatting is platform-dependent and should not be parsed.
func InterfaceDebugExtras(ifIndex int) (string, error) {
	if interfaceDebugExtras != nil {
		return interfaceDebugExtras(ifIndex)
	}
	return "", nil
}

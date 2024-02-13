/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package router

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"sort"
	"time"

	ole "github.com/go-ole/go-ole"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/health"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tstun"
	"tailscale.com/util/multierr"
	"tailscale.com/wgengine/winnet"
)

// monitorDefaultRoutes subscribes to route change events and updates
// the Tailscale tunnel interface's MTU to match that of the
// underlying default route.
//
// This is an attempt at making the MTU mostly correct, but in
// practice this entire piece of code ends up just using the 1280
// value passed in at device construction time. This code might make
// the MTU go lower due to very low-MTU IPv4 interfaces.
//
// TODO: this code is insufficient to control the MTU correctly. The
// correct way to do it is per-peer PMTU discovery, and synthesizing
// ICMP fragmentation-needed messages within tailscaled. This code may
// address a few rare corner cases, but is unlikely to significantly
// help with MTU issues compared to a static 1280B implementation.
func monitorDefaultRoutes(tun *tun.NativeTun) (*winipcfg.RouteChangeCallback, error) {
	ourLuid := winipcfg.LUID(tun.LUID())
	lastMtu := uint32(0)
	doIt := func() error {
		mtu, err := getDefaultRouteMTU()
		if err != nil {
			return fmt.Errorf("error getting default route MTU: %w", err)
		}

		if mtu > 0 && (lastMtu == 0 || lastMtu != mtu) {
			iface, err := ourLuid.IPInterface(windows.AF_INET)
			if err != nil {
				if !errors.Is(err, windows.ERROR_NOT_FOUND) {
					return fmt.Errorf("getting v4 interface: %w", err)
				}
			} else {
				iface.NLMTU = mtu - 80
				// If the TUN device was created with a smaller MTU,
				// though, such as 1280, we don't want to go bigger
				// than configured. (See the comment on minimalMTU in
				// the wgengine package.)
				if min, err := tun.MTU(); err == nil && min < int(iface.NLMTU) {
					iface.NLMTU = uint32(min)
				}
				if iface.NLMTU < 576 {
					iface.NLMTU = 576
				}
				err = iface.Set()
				if err != nil {
					return fmt.Errorf("error setting v4 MTU: %w", err)
				}
				tun.ForceMTU(int(iface.NLMTU))
			}
			iface, err = ourLuid.IPInterface(windows.AF_INET6)
			if err != nil {
				if !errors.Is(err, windows.ERROR_NOT_FOUND) {
					return fmt.Errorf("error getting v6 interface: %w", err)
				}
			} else {
				iface.NLMTU = mtu - 80
				if iface.NLMTU < 1280 {
					iface.NLMTU = 1280
				}
				err = iface.Set()
				if err != nil {
					return fmt.Errorf("error setting v6 MTU: %w", err)
				}
			}
			lastMtu = mtu
		}
		return nil
	}
	err := doIt()
	if err != nil {
		return nil, err
	}
	cb, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		//fmt.Printf("MonitorDefaultRoutes: changed: %v\n", route.DestinationPrefix)
		if route.DestinationPrefix.PrefixLength == 0 {
			_ = doIt()
		}
	})
	if err != nil {
		return nil, err
	}
	return cb, nil
}

func getDefaultRouteMTU() (uint32, error) {
	mtus, err := interfaces.NonTailscaleMTUs()
	if err != nil {
		return 0, err
	}

	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return 0, err
	}
	best := ^uint32(0)
	mtu := uint32(0)
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		routeMTU := mtus[route.InterfaceLUID]
		if routeMTU == 0 {
			continue
		}
		if route.Metric < best {
			best = route.Metric
			mtu = routeMTU
		}
	}

	routes, err = winipcfg.GetIPForwardTable2(windows.AF_INET6)
	if err != nil {
		return 0, err
	}
	best = ^uint32(0)
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		routeMTU := mtus[route.InterfaceLUID]
		if routeMTU == 0 {
			continue
		}
		if route.Metric < best {
			best = route.Metric
			if routeMTU < mtu {
				mtu = routeMTU
			}
		}
	}

	return mtu, nil
}

// setPrivateNetwork marks the provided network adapter's category to private.
// It returns (false, nil) if the adapter was not found.
func setPrivateNetwork(ifcLUID winipcfg.LUID) (bool, error) {
	// NLM_NETWORK_CATEGORY values.
	const (
		categoryPublic  = 0
		categoryPrivate = 1
		categoryDomain  = 2
	)

	ifcGUID, err := ifcLUID.GUID()
	if err != nil {
		return false, fmt.Errorf("ifcLUID.GUID: %v", err)
	}

	// aaron: DO NOT call Initialize() or Uninitialize() on c!
	// We've already handled that process-wide.
	var c ole.Connection

	m, err := winnet.NewNetworkListManager(&c)
	if err != nil {
		return false, fmt.Errorf("winnet.NewNetworkListManager: %v", err)
	}
	defer m.Release()

	cl, err := m.GetNetworkConnections()
	if err != nil {
		return false, fmt.Errorf("m.GetNetworkConnections: %v", err)
	}
	defer cl.Release()

	for _, nco := range cl {
		aid, err := nco.GetAdapterId()
		if err != nil {
			return false, fmt.Errorf("nco.GetAdapterId: %v", err)
		}
		if aid != ifcGUID.String() {
			continue
		}

		n, err := nco.GetNetwork()
		if err != nil {
			return false, fmt.Errorf("GetNetwork: %v", err)
		}
		defer n.Release()

		cat, err := n.GetCategory()
		if err != nil {
			return false, fmt.Errorf("GetCategory: %v", err)
		}

		if cat != categoryPrivate {
			if err := n.SetCategory(categoryPrivate); err != nil {
				return false, fmt.Errorf("SetCategory: %v", err)
			}
		}
		return true, nil
	}

	return false, nil
}

// interfaceFromLUID returns IPAdapterAddresses with specified LUID.
func interfaceFromLUID(luid winipcfg.LUID, flags winipcfg.GAAFlags) (*winipcfg.IPAdapterAddresses, error) {
	addresses, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, flags)
	if err != nil {
		return nil, err
	}
	for _, addr := range addresses {
		if addr.LUID == luid {
			return addr, nil
		}
	}
	return nil, fmt.Errorf("interfaceFromLUID: interface with LUID %v not found", luid)
}

var networkCategoryWarning = health.NewWarnable(health.WithMapDebugFlag("warn-network-category-unhealthy"))

func configureInterface(cfg *Config, tun *tun.NativeTun) (retErr error) {
	var mtu = tstun.DefaultTUNMTU()
	luid := winipcfg.LUID(tun.LUID())
	iface, err := interfaceFromLUID(luid,
		// Issue 474: on early boot, when the network is still
		// coming up, if the Tailscale service comes up first,
		// the Tailscale adapter it finds might not have the
		// IPv4 service available yet? Try this flag:
		winipcfg.GAAFlagIncludeAllInterfaces,
	)
	if err != nil {
		return fmt.Errorf("getting interface: %w", err)
	}

	// Send non-nil return errors to retErrc, to interrupt our background
	// setPrivateNetwork goroutine.
	retErrc := make(chan error, 1)
	defer func() {
		if retErr != nil {
			retErrc <- retErr
		}
	}()

	go func() {
		// It takes a weirdly long time for Windows to notice the
		// new interface has come up. Poll periodically until it
		// does.
		const tries = 20
		for i := 0; i < tries; i++ {
			found, err := setPrivateNetwork(luid)
			if err != nil {
				networkCategoryWarning.Set(fmt.Errorf("set-network-category: %w", err))
				log.Printf("setPrivateNetwork(try=%d): %v", i, err)
			} else {
				networkCategoryWarning.Set(nil)
				if found {
					if i > 0 {
						log.Printf("setPrivateNetwork(try=%d): success", i)
					}
					return
				}
				log.Printf("setPrivateNetwork(try=%d): not found", i)
			}
			select {
			case <-time.After(time.Second):
			case <-retErrc:
				return
			}
		}
		log.Printf("setPrivateNetwork: adapter LUID %v not found after %d tries, giving up", luid, tries)
	}()

	// Figure out which of IPv4 and IPv6 are available. Both protocols
	// can be disabled on a per-interface basis by the user, as well
	// as globally via a registry policy. We skip programming anything
	// related to the disabled protocols, since by definition they're
	// unusable.
	ipif4, err := iface.LUID.IPInterface(windows.AF_INET)
	if err != nil {
		if !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return fmt.Errorf("getting AF_INET interface: %w", err)
		}
		log.Printf("AF_INET interface not found on Tailscale adapter, skipping IPv4 programming")
		ipif4 = nil
	}
	ipif6, err := iface.LUID.IPInterface(windows.AF_INET6)
	if err != nil {
		if !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return fmt.Errorf("getting AF_INET6 interface: %w", err)
		}
		log.Printf("AF_INET6 interface not found on Tailscale adapter, skipping IPv6 programming")
		ipif6 = nil
	}

	// Windows requires routes to have a nexthop. For routes such as
	// ours where the nexthop is meaningless, you're supposed to use
	// one of the local IP addresses of the interface. Find an IPv4
	// and IPv6 address we can use for this purpose.
	var firstGateway4 netip.Addr
	var firstGateway6 netip.Addr
	addresses := make([]netip.Prefix, 0, len(cfg.LocalAddrs))
	for _, addr := range cfg.LocalAddrs {
		if (addr.Addr().Is4() && ipif4 == nil) || (addr.Addr().Is6() && ipif6 == nil) {
			// Can't program addresses for disabled protocol.
			continue
		}
		addresses = append(addresses, addr)
		if addr.Addr().Is4() && !firstGateway4.IsValid() {
			firstGateway4 = addr.Addr()
		} else if addr.Addr().Is6() && !firstGateway6.IsValid() {
			firstGateway6 = addr.Addr()
		}
	}

	var routes []*routeData
	foundDefault4 := false
	foundDefault6 := false
	for _, route := range cfg.Routes {
		if (route.Addr().Is4() && ipif4 == nil) || (route.Addr().Is6() && ipif6 == nil) {
			// Can't program routes for disabled protocol.
			continue
		}

		if route.Addr().Is6() && !firstGateway6.IsValid() {
			// Windows won't let us set IPv6 routes without having an
			// IPv6 local address set. However, when we've configured
			// a default route, we want to forcibly grab IPv6 traffic
			// even if the v6 overlay network isn't configured. To do
			// that, we add a dummy local IPv6 address to serve as a
			// route source.
			ip := tsaddr.Tailscale4To6Placeholder()
			addresses = append(addresses, netip.PrefixFrom(ip, ip.BitLen()))
			firstGateway6 = ip
		} else if route.Addr().Is4() && !firstGateway4.IsValid() {
			// TODO: do same dummy behavior as v6?
			return errors.New("due to a Windows limitation, one cannot have interface routes without an interface address")
		}

		var gateway netip.Addr
		if route.Addr().Is4() {
			gateway = firstGateway4
		} else if route.Addr().Is6() {
			gateway = firstGateway6
		}
		r := &routeData{
			RouteData: winipcfg.RouteData{
				Destination: route,
				NextHop:     gateway,
				Metric:      0,
			},
		}
		if r.Destination.Addr().Unmap() == gateway {
			// no need to add a route for the interface's
			// own IP. The kernel does that for us.
			// If we try to replace it, we'll fail to
			// add the route unless NextHop is set, but
			// then the interface's IP won't be pingable.
			continue
		}
		if route.Addr().Is4() {
			if route.Bits() == 0 {
				foundDefault4 = true
			}
			r.NextHop = firstGateway4
		} else if route.Addr().Is6() {
			if route.Bits() == 0 {
				foundDefault6 = true
			}
			r.NextHop = firstGateway6
		}
		routes = append(routes, r)
	}

	err = syncAddresses(iface, addresses)
	if err != nil {
		return fmt.Errorf("syncAddresses: %w", err)
	}

	slices.SortFunc(routes, (*routeData).Compare)

	deduplicatedRoutes := []*routeData{}
	for i := 0; i < len(routes); i++ {
		// There's only one way to get to a given IP+Mask, so delete
		// all matches after the first.
		if i > 0 && routes[i].Destination == routes[i-1].Destination {
			continue
		}
		deduplicatedRoutes = append(deduplicatedRoutes, routes[i])
	}

	// Re-read interface after syncAddresses.
	iface, err = interfaceFromLUID(luid,
		// Issue 474: on early boot, when the network is still
		// coming up, if the Tailscale service comes up first,
		// the Tailscale adapter it finds might not have the
		// IPv4 service available yet? Try this flag:
		winipcfg.GAAFlagIncludeAllInterfaces,
	)
	if err != nil {
		return fmt.Errorf("getting interface: %w", err)
	}

	var errAcc error
	err = syncRoutes(iface, deduplicatedRoutes, cfg.LocalAddrs)
	if err != nil && errAcc == nil {
		log.Printf("setroutes: %v", err)
		errAcc = err
	}

	if ipif4 != nil {
		ipif4, err = iface.LUID.IPInterface(windows.AF_INET)
		if err != nil {
			return fmt.Errorf("getting AF_INET interface: %w", err)
		}
		if foundDefault4 {
			ipif4.UseAutomaticMetric = false
			ipif4.Metric = 0
		}
		if mtu > 0 {
			ipif4.NLMTU = uint32(mtu)
			tun.ForceMTU(int(ipif4.NLMTU))
		}
		err = ipif4.Set()
		if err != nil && errAcc == nil {
			errAcc = err
		}
	}

	if ipif6 != nil {
		ipif6, err = iface.LUID.IPInterface(windows.AF_INET6)
		if err != nil {
			return fmt.Errorf("getting AF_INET6 interface: %w", err)
		} else {
			if foundDefault6 {
				ipif6.UseAutomaticMetric = false
				ipif6.Metric = 0
			}
			if mtu > 0 {
				ipif6.NLMTU = uint32(mtu)
			}
			ipif6.DadTransmits = 0
			ipif6.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
			err = ipif6.Set()
			if err != nil && errAcc == nil {
				errAcc = err
			}
		}
	}

	return errAcc
}

func netCompare(a, b netip.Prefix) int {
	aip, bip := a.Addr().Unmap(), b.Addr().Unmap()
	v := aip.Compare(bip)
	if v != 0 {
		return v
	}

	if a.Bits() == b.Bits() {
		return 0
	}
	// narrower first
	if a.Bits() > b.Bits() {
		return -1
	}
	return 1
}

func sortNets(s []netip.Prefix) {
	sort.Slice(s, func(i, j int) bool {
		return netCompare(s[i], s[j]) == -1
	})
}

// deltaNets returns the changes to turn a into b.
func deltaNets(a, b []netip.Prefix) (add, del []netip.Prefix) {
	add = make([]netip.Prefix, 0, len(b))
	del = make([]netip.Prefix, 0, len(a))
	sortNets(a)
	sortNets(b)

	i := 0
	j := 0
	for i < len(a) && j < len(b) {
		switch netCompare(a[i], b[j]) {
		case -1:
			// a < b, delete
			del = append(del, a[i])
			i++
		case 0:
			// a == b, no diff
			i++
			j++
		case 1:
			// a > b, add missing entry
			add = append(add, b[j])
			j++
		default:
			panic("unexpected compare result")
		}
	}
	del = append(del, a[i:]...)
	add = append(add, b[j:]...)
	return
}

func isIPv6LinkLocal(a netip.Prefix) bool {
	return a.Addr().Is6() && a.Addr().IsLinkLocalUnicast()
}

// ipAdapterUnicastAddressToPrefix converts windows.IpAdapterUnicastAddress to netip.Prefix
func ipAdapterUnicastAddressToPrefix(u *windows.IpAdapterUnicastAddress) netip.Prefix {
	ip, _ := netip.AddrFromSlice(u.Address.IP())
	return netip.PrefixFrom(ip.Unmap(), int(u.OnLinkPrefixLength))
}

// unicastIPNets returns all unicast net.IPNet for ifc interface.
func unicastIPNets(ifc *winipcfg.IPAdapterAddresses) []netip.Prefix {
	var nets []netip.Prefix
	for addr := ifc.FirstUnicastAddress; addr != nil; addr = addr.Next {
		nets = append(nets, ipAdapterUnicastAddressToPrefix(addr))
	}
	return nets
}

// syncAddresses incrementally sets the interface's unicast IP addresses,
// doing the minimum number of AddAddresses & DeleteAddress calls.
// This avoids the full FlushAddresses.
//
// Any IPv6 link-local addresses are not deleted out of caution as some
// configurations may repeatedly re-add them. Link-local addresses are adjusted
// to set SkipAsSource. SkipAsSource prevents the addresses from being added to
// DNS locally or remotely and from being picked as a source address for
// outgoing packets with unspecified sources. See #4647 and
// https://web.archive.org/web/20200912120956/https://devblogs.microsoft.com/scripting/use-powershell-to-change-ip-behavior-with-skipassource/
func syncAddresses(ifc *winipcfg.IPAdapterAddresses, want []netip.Prefix) error {
	var erracc error

	got := unicastIPNets(ifc)
	add, del := deltaNets(got, want)

	ll := make([]netip.Prefix, 0)
	for _, a := range del {
		// do not delete link-local addresses, and collect them for later
		// applying SkipAsSource.
		if isIPv6LinkLocal(a) {
			ll = append(ll, a)
			continue
		}

		err := ifc.LUID.DeleteIPAddress(a)
		if err != nil {
			erracc = fmt.Errorf("deleting IP %q: %w", a, err)
		}
	}

	for _, a := range add {
		err := ifc.LUID.AddIPAddress(a)
		if err != nil {
			erracc = fmt.Errorf("adding IP %q: %w", a, err)
		}
	}

	for _, a := range ll {
		mib, err := ifc.LUID.IPAddress(a.Addr())
		if err != nil {
			erracc = fmt.Errorf("setting skip-as-source on IP %q: unable to retrieve MIB: %w", a, err)
			continue
		}
		if !mib.SkipAsSource {
			mib.SkipAsSource = true
			if err := mib.Set(); err != nil {
				erracc = fmt.Errorf("setting skip-as-source on IP %q: unable to set MIB: %w", a, err)
			}
		}
	}

	return erracc
}

// routeData wraps winipcfg.RouteData with an additional field that permits
// caching of the associated MibIPForwardRow2; by keeping it around, we can
// avoid unnecessary (and slow) lookups of information that we already have.
type routeData struct {
	winipcfg.RouteData
	Row *winipcfg.MibIPforwardRow2
}

func (rd *routeData) Less(other *routeData) bool {
	return rd.Compare(other) < 0
}

func (rd *routeData) Compare(other *routeData) int {
	v := rd.Destination.Addr().Compare(other.Destination.Addr())
	if v != 0 {
		return v
	}

	// Narrower masks first
	b1, b2 := rd.Destination.Bits(), other.Destination.Bits()
	if b1 != b2 {
		if b1 > b2 {
			return -1
		}
		return 1
	}

	// No nexthop before non-empty nexthop
	v = rd.NextHop.Compare(other.NextHop)
	if v != 0 {
		return v
	}

	// Lower metrics first
	if rd.Metric < other.Metric {
		return -1
	} else if rd.Metric > other.Metric {
		return 1
	}

	return 0
}

func deltaRouteData(a, b []*routeData) (add, del []*routeData) {
	add = make([]*routeData, 0, len(b))
	del = make([]*routeData, 0, len(a))
	slices.SortFunc(a, (*routeData).Compare)
	slices.SortFunc(b, (*routeData).Compare)

	i := 0
	j := 0
	for i < len(a) && j < len(b) {
		switch a[i].Compare(b[j]) {
		case -1:
			// a < b, delete
			del = append(del, a[i])
			i++
		case 0:
			// a == b, no diff
			i++
			j++
		case 1:
			// a > b, add missing entry
			add = append(add, b[j])
			j++
		default:
			panic("unexpected compare result")
		}
	}
	del = append(del, a[i:]...)
	add = append(add, b[j:]...)
	return
}

// getInterfaceRoutes returns all the interface's routes.
// Corresponds to GetIpForwardTable2 function, but filtered by interface.
func getInterfaceRoutes(ifc *winipcfg.IPAdapterAddresses, family winipcfg.AddressFamily) (matches []*winipcfg.MibIPforwardRow2, err error) {
	routes, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return nil, err
	}
	for i := range routes {
		if routes[i].InterfaceLUID == ifc.LUID {
			matches = append(matches, &routes[i])
		}
	}
	return
}

func getAllInterfaceRoutes(ifc *winipcfg.IPAdapterAddresses) ([]*routeData, error) {
	routes4, err := getInterfaceRoutes(ifc, windows.AF_INET)
	if err != nil {
		return nil, err
	}

	routes6, err := getInterfaceRoutes(ifc, windows.AF_INET6)
	if err != nil {
		// TODO: what if v6 unavailable?
		return nil, err
	}

	rd := make([]*routeData, 0, len(routes4)+len(routes6))
	for _, r := range routes4 {
		rd = append(rd, &routeData{
			RouteData: winipcfg.RouteData{
				Destination: r.DestinationPrefix.Prefix(),
				NextHop:     r.NextHop.Addr(),
				Metric:      r.Metric,
			},
			Row: r,
		})
	}

	for _, r := range routes6 {
		rd = append(rd, &routeData{
			RouteData: winipcfg.RouteData{
				Destination: r.DestinationPrefix.Prefix(),
				NextHop:     r.NextHop.Addr(),
				Metric:      r.Metric,
			},
			Row: r,
		})
	}
	return rd, nil
}

// filterRoutes removes routes that have been added by Windows and should not
// be managed by us.
func filterRoutes(routes []*routeData, dontDelete []netip.Prefix) []*routeData {
	ddm := make(map[netip.Prefix]bool)
	for _, dd := range dontDelete {
		// See issue 1448: we don't want to touch the routes added
		// by Windows for our interface addresses.
		ddm[dd] = true
	}
	for _, r := range routes {
		// We don't want to touch broadcast routes that Windows adds.
		nr := r.Destination
		if !nr.IsValid() {
			continue
		}
		if nr.IsSingleIP() {
			continue
		}
		lastIP := netipx.RangeOfPrefix(nr).To()
		ddm[netip.PrefixFrom(lastIP, lastIP.BitLen())] = true
	}
	filtered := make([]*routeData, 0, len(routes))
	for _, r := range routes {
		rr := r.Destination
		if rr.IsValid() && ddm[rr] {
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}

// syncRoutes incrementally sets multiples routes on an interface.
// This avoids a full ifc.FlushRoutes call.
// dontDelete is a list of interface address routes that the
// synchronization logic should never delete.
func syncRoutes(ifc *winipcfg.IPAdapterAddresses, want []*routeData, dontDelete []netip.Prefix) error {
	existingRoutes, err := getAllInterfaceRoutes(ifc)
	if err != nil {
		return err
	}
	got := filterRoutes(existingRoutes, dontDelete)

	add, del := deltaRouteData(got, want)

	var errs []error
	for _, a := range del {
		var err error
		if a.Row == nil {
			// DeleteRoute requires a routing table lookup, so only do that if
			// a does not already have the row.
			err = ifc.LUID.DeleteRoute(a.Destination, a.NextHop)
		} else {
			// Otherwise, delete the row directly.
			err = a.Row.Delete()
		}
		if err != nil {
			dstStr := a.Destination.String()
			if dstStr == "169.254.255.255/32" {
				// Issue 785. Ignore these routes
				// failing to delete. Harmless.
				// TODO(maisem): do we still need this?
				continue
			}
			errs = append(errs, fmt.Errorf("deleting route %v: %w", dstStr, err))
		}
	}

	for _, a := range add {
		err := ifc.LUID.AddRoute(a.Destination, a.NextHop, a.Metric)
		if err != nil {
			errs = append(errs, fmt.Errorf("adding route %v: %w", &a.Destination, err))
		}
	}

	return multierr.New(errs...)
}

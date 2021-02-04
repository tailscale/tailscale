/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package router

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"sort"
	"tailscale.com/log/filelogger"
	"time"

	"github.com/go-multierror/multierror"
	ole "github.com/go-ole/go-ole"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/net/interfaces"
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
	filelogger.WinApiLogger("monitorDefaultRoutes(%v)\n", tun)
	ourLuid := winipcfg.LUID(tun.LUID())
	filelogger.WinApiLogger("monitorDefaultRoutes: ourLuid = %v\n", ourLuid)
	lastMtu := uint32(0)
	doIt := func() error {
		mtu, err := getDefaultRouteMTU()
		if err != nil {
			return fmt.Errorf("error getting default route MTU: %w", err)
		}

		if mtu > 0 && (lastMtu == 0 || lastMtu != mtu) {
			iface, err := ourLuid.IPInterface(windows.AF_INET)
			if err != nil {
				filelogger.WinApiLogger("monitorDefaultRoutes/doIt: ourLuid[%v].IPInterface(windows.AF_INET) ERROR:\n%v\n",
					ourLuid, err)
				return fmt.Errorf("error getting v4 interface: %w", err)
			} else {
				filelogger.WinApiLogger("monitorDefaultRoutes/doIt: ourLuid[%v].IPInterface(windows.AF_INET) SUCCESS:\n%v\n",
					ourLuid, iface)
			}
			iface.NLMTU = mtu - 80
			// If the TUN device was created with a smaller MTU,
			// though, such as 1280, we don't want to go bigger than
			// configured. (See the comment on minimalMTU in the
			// wgengine package.)
			if min, err := tun.MTU(); err == nil && min < int(iface.NLMTU) {
				iface.NLMTU = uint32(min)
			}
			if iface.NLMTU < 576 {
				iface.NLMTU = 576
			}
			err = iface.Set()
			if err != nil {
				filelogger.WinApiLogger("monitorDefaultRoutes/doIt: iface[v4].Set() ERROR:\n%v\n", err)
				return fmt.Errorf("error setting v4 MTU: %w", err)
			} else {
				filelogger.WinApiLogger("monitorDefaultRoutes/doIt: iface[v4].Set() SUCCESS\n")
			}
			tun.ForceMTU(int(iface.NLMTU))
			iface, err = ourLuid.IPInterface(windows.AF_INET6)
			if err != nil {
				if !errors.Is(err, windows.ERROR_NOT_FOUND) {
					filelogger.WinApiLogger("monitorDefaultRoutes/doIt: ourLuid[%v].IPInterface(windows.AF_INET6) ERROR:\n%v\n",
						ourLuid, err)
					return fmt.Errorf("error getting v6 interface: %w", err)
				}
			} else {
				filelogger.WinApiLogger("monitorDefaultRoutes/doIt: ourLuid[%v].IPInterface(windows.AF_INET6) SUCCESS:\n%v\n",
					ourLuid, iface)
				iface.NLMTU = mtu - 80
				if iface.NLMTU < 1280 {
					iface.NLMTU = 1280
				}
				err = iface.Set()
				if err != nil {
					filelogger.WinApiLogger("monitorDefaultRoutes/doIt: iface[v6].Set() ERROR:\n%v\n", err)
					return fmt.Errorf("error setting v6 MTU: %w", err)
				} else {
					filelogger.WinApiLogger("monitorDefaultRoutes/doIt: iface[v6].Set() SUCCESS\n")
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
		filelogger.WinApiLogger("monitorDefaultRoutes: RouteChangeCallback(%v, %v)\n", notificationType, route)
		//fmt.Printf("MonitorDefaultRoutes: changed: %v\n", route.DestinationPrefix)
		if route.DestinationPrefix.PrefixLength == 0 {
			_ = doIt()
		}
	})
	if err != nil {
		filelogger.WinApiLogger("monitorDefaultRoutes: winipcfg.RegisterRouteChangeCallback() ERROR:\n%v\n", err)
		return nil, err
	}
	filelogger.WinApiLogger("monitorDefaultRoutes: winipcfg.RegisterRouteChangeCallback() SUCCESS\n")
	return cb, nil
}

func getDefaultRouteMTU() (uint32, error) {
	filelogger.WinApiLogger("getDefaultRouteMTU()\n")
	mtus, err := interfaces.NonTailscaleMTUs()
	if err != nil {
		return 0, err
	}

	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		filelogger.WinApiLogger("getDefaultRouteMTU: winipcfg.GetIPForwardTable2(windows.AF_INET) ERROR:\n%v\n",
			err)
		return 0, err
	} else {
		filelogger.WinApiLogger("getDefaultRouteMTU: winipcfg.GetIPForwardTable2(windows.AF_INET) SUCCESS:\n%v\n",
			routes)
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
		filelogger.WinApiLogger("getDefaultRouteMTU: winipcfg.GetIPForwardTable2(windows.AF_INET6) ERROR:\n%v\n", err)
		return 0, err
	} else {
		filelogger.WinApiLogger("getDefaultRouteMTU: winipcfg.GetIPForwardTable2(windows.AF_INET6) SUCCESS:\n%v\n",
			routes)
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
	filelogger.WinApiLogger("setPrivateNetwork(%v)\n", ifcLUID)
	// NLM_NETWORK_CATEGORY values.
	const (
		categoryPublic  = 0
		categoryPrivate = 1
		categoryDomain  = 2
	)

	ifcGUID, err := ifcLUID.GUID()
	if err != nil {
		filelogger.WinApiLogger("setPrivateNetwork: ifcLUID[%v].GUID() ERROR:\n%v\n", ifcLUID, err)
		return false, fmt.Errorf("ifcLUID.GUID: %v", err)
	}
	filelogger.WinApiLogger("setPrivateNetwork: ifcLUID[%v].GUID() SUCCESS:\n%v\n", ifcLUID, ifcGUID)

	// Lock OS thread when using OLE, which seems to be a requirement
	// from the Microsoft docs. go-ole doesn't seem to handle it automatically.
	// https://github.com/tailscale/tailscale/issues/921#issuecomment-727526807
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var c ole.Connection
	if err := c.Initialize(); err != nil {
		filelogger.WinApiLogger("setPrivateNetwork: c.Initialize() ERROR:\n%v\n", err)
		return false, fmt.Errorf("c.Initialize: %v", err)
	}
	defer c.Uninitialize()
	filelogger.WinApiLogger("setPrivateNetwork: c.Initialize() SUCCESS:\n")

	m, err := winnet.NewNetworkListManager(&c)
	if err != nil {
		filelogger.WinApiLogger("setPrivateNetwork: winnet.NewNetworkListManager() ERROR:\n%v\n", err)
		return false, fmt.Errorf("winnet.NewNetworkListManager: %v", err)
	}
	defer m.Release()
	filelogger.WinApiLogger("setPrivateNetwork: winnet.NewNetworkListManager() SUCCESS\n")

	cl, err := m.GetNetworkConnections()
	if err != nil {
		filelogger.WinApiLogger("setPrivateNetwork: m.GetNetworkConnections() ERROR:\n%v\n", err)
		return false, fmt.Errorf("m.GetNetworkConnections: %v", err)
	}
	defer cl.Release()
	filelogger.WinApiLogger("setPrivateNetwork: m.GetNetworkConnections() SUCCESS\n")

	for _, nco := range cl {
		aid, err := nco.GetAdapterId()
		if err != nil {
			filelogger.WinApiLogger("setPrivateNetwork: nco.GetAdapterId() ERROR:\n%v\nnco: %v\n", err, nco)
			return false, fmt.Errorf("nco.GetAdapterId: %v", err)
		}
		filelogger.WinApiLogger("setPrivateNetwork: nco.GetAdapterId() SUCCESS:\n%v\nnco: %v\n", aid, nco)
		if aid != ifcGUID.String() {
			continue
		}

		n, err := nco.GetNetwork()
		if err != nil {
			filelogger.WinApiLogger("setPrivateNetwork: nco.GetNetwork() ERROR:\n%v\nnco: %v\n", err, nco)
			return false, fmt.Errorf("GetNetwork: %v", err)
		}
		defer n.Release()
		filelogger.WinApiLogger("setPrivateNetwork: nco.GetNetwork() SUCCESS:\n%v\nnco: %v\n", n, nco)

		cat, err := n.GetCategory()
		if err != nil {
			filelogger.WinApiLogger("setPrivateNetwork: n.GetCategory() ERROR:\n%v\nn: %v\n", err, n)
			return false, fmt.Errorf("GetCategory: %v", err)
		}
		filelogger.WinApiLogger("setPrivateNetwork: n.GetCategory() SUCCESS:\n%v\nn: %v\n", cat, n)

		if cat != categoryPrivate {
			if err := n.SetCategory(categoryPrivate); err != nil {
				filelogger.WinApiLogger("setPrivateNetwork: n.SetCategory(categoryPrivate) ERROR:\n%v\nn: %v\n",
					err, n)
				return false, fmt.Errorf("SetCategory: %v", err)
			}
			filelogger.WinApiLogger("setPrivateNetwork: n.SetCategory(categoryPrivate) SUCCESS\nn: %v\n", n)
		}
		return true, nil
	}

	return false, nil
}

// interfaceFromLUID returns IPAdapterAddresses with specified LUID.
func interfaceFromLUID(luid winipcfg.LUID, flags winipcfg.GAAFlags) (*winipcfg.IPAdapterAddresses, error) {
	filelogger.WinApiLogger("interfaceFromLUID(%v, %v)\n", luid, flags)
	addresses, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, flags)
	if err != nil {
		filelogger.WinApiLogger("interfaceFromLUID: winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, %v) ERROR:\n%v\n",
			flags, err)
		return nil, err
	}
	filelogger.WinApiLogger("interfaceFromLUID: winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, %v) SUCCESS:\n%v\n",
		flags, addresses)
	for _, addr := range addresses {
		if addr.LUID == luid {
			return addr, nil
		}
	}
	filelogger.WinApiLogger("interfaceFromLUID: interface with LUID %v not found\n", luid)
	return nil, fmt.Errorf("interfaceFromLUID: interface with LUID %v not found", luid)
}

func configureInterface(cfg *Config, tun *tun.NativeTun) (retErr error) {
	filelogger.WinApiLogger("configureInterface(%v, %v)\n", cfg, tun)
	const mtu = 0
	luid := winipcfg.LUID(tun.LUID())
	iface, err := interfaceFromLUID(luid,
		// Issue 474: on early boot, when the network is still
		// coming up, if the Tailscale service comes up first,
		// the Tailscale adapter it finds might not have the
		// IPv4 service available yet? Try this flag:
		winipcfg.GAAFlagIncludeAllInterfaces,
	)
	if err != nil {
		return err
	}

	// Send non-nil return errors to retErrc, to interupt our background
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
				log.Printf("setPrivateNetwork(try=%d): %v", i, err)
			} else {
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

	var firstGateway4 *net.IP
	var firstGateway6 *net.IP
	addresses := make([]*net.IPNet, len(cfg.LocalAddrs))
	for i, addr := range cfg.LocalAddrs {
		ipnet := addr.IPNet()
		addresses[i] = ipnet
		gateway := ipnet.IP
		if addr.IP.Is4() && firstGateway4 == nil {
			firstGateway4 = &gateway
		} else if addr.IP.Is6() && firstGateway6 == nil {
			firstGateway6 = &gateway
		}
	}

	var routes []winipcfg.RouteData
	foundDefault4 := false
	foundDefault6 := false
	for _, route := range cfg.Routes {
		if (route.IP.Is4() && firstGateway4 == nil) || (route.IP.Is6() && firstGateway6 == nil) {
			return errors.New("Due to a Windows limitation, one cannot have interface routes without an interface address")
		}

		ipn := route.IPNet()
		var gateway net.IP
		if route.IP.Is4() {
			gateway = *firstGateway4
		} else if route.IP.Is6() {
			gateway = *firstGateway6
		}
		r := winipcfg.RouteData{
			Destination: net.IPNet{
				IP:   ipn.IP.Mask(ipn.Mask),
				Mask: ipn.Mask,
			},
			NextHop: gateway,
			Metric:  0,
		}
		if bytes.Compare(r.Destination.IP, gateway) == 0 {
			// no need to add a route for the interface's
			// own IP. The kernel does that for us.
			// If we try to replace it, we'll fail to
			// add the route unless NextHop is set, but
			// then the interface's IP won't be pingable.
			continue
		}
		if route.IP.Is4() {
			if route.Bits == 0 {
				foundDefault4 = true
			}
			r.NextHop = *firstGateway4
		} else if route.IP.Is6() {
			if route.Bits == 0 {
				foundDefault6 = true
			}
			r.NextHop = *firstGateway6
		}
		routes = append(routes, r)
	}

	err = syncAddresses(iface, addresses)
	if err != nil {
		return err
	}

	sort.Slice(routes, func(i, j int) bool { return routeLess(&routes[i], &routes[j]) })

	deduplicatedRoutes := []*winipcfg.RouteData{}
	for i := 0; i < len(routes); i++ {
		// There's only one way to get to a given IP+Mask, so delete
		// all matches after the first.
		if i > 0 &&
			bytes.Equal(routes[i].Destination.IP, routes[i-1].Destination.IP) &&
			bytes.Equal(routes[i].Destination.Mask, routes[i-1].Destination.Mask) {
			continue
		}
		deduplicatedRoutes = append(deduplicatedRoutes, &routes[i])
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
		return err
	}

	var errAcc error
	err = syncRoutes(iface, deduplicatedRoutes)
	if err != nil && errAcc == nil {
		log.Printf("setroutes: %v", err)
		errAcc = err
	}

	//ipif, err := iface.LUID.IPInterface(windows.AF_INET)
	ipif, err := getIpInterface(iface, windows.AF_INET)
	if err != nil {
		log.Printf("getipif: %v", err)
		return err
	}
	if foundDefault4 {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}
	if mtu > 0 {
		ipif.NLMTU = uint32(mtu)
		tun.ForceMTU(int(ipif.NLMTU))
	}
	err = ipif.Set()
	if err != nil && errAcc == nil {
		errAcc = err
	}

	//ipif, err = iface.LUID.IPInterface(windows.AF_INET6)
	ipif, err = getIpInterface(iface, windows.AF_INET6);
	if err != nil {
		if !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return err
		}
	} else {
		if foundDefault6 {
			ipif.UseAutomaticMetric = false
			ipif.Metric = 0
		}
		if mtu > 0 {
			ipif.NLMTU = uint32(mtu)
		}
		ipif.DadTransmits = 0
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		err = ipif.Set()
		if err != nil && errAcc == nil {
			errAcc = err
		}
	}

	return errAcc
}

// routeLess reports whether ri should sort before rj.
// The actual sort order doesn't appear to matter. The caller just
// wants them sorted to be able to de-dup.
func routeLess(ri, rj *winipcfg.RouteData) bool {
	if v := bytes.Compare(ri.Destination.IP, rj.Destination.IP); v != 0 {
		return v == -1
	}
	if v := bytes.Compare(ri.Destination.Mask, rj.Destination.Mask); v != 0 {
		// Narrower masks first
		return v == 1
	}
	if ri.Metric != rj.Metric {
		// Lower metrics first
		return ri.Metric < rj.Metric
	}
	if v := bytes.Compare(ri.NextHop, rj.NextHop); v != 0 {
		// No nexthop before non-empty nexthop.
		return v == -1
	}
	return false
}

// unwrapIP returns the shortest version of ip.
func unwrapIP(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}

func v4Mask(m net.IPMask) net.IPMask {
	if len(m) == 16 {
		return m[12:]
	}
	return m
}

func netCompare(a, b net.IPNet) int {
	aip, bip := unwrapIP(a.IP), unwrapIP(b.IP)
	v := bytes.Compare(aip, bip)
	if v != 0 {
		return v
	}

	amask, bmask := a.Mask, b.Mask
	if len(aip) == 4 {
		amask = v4Mask(a.Mask)
		bmask = v4Mask(b.Mask)
	}

	// narrower first
	return -bytes.Compare(amask, bmask)
}

func sortNets(a []*net.IPNet) {
	sort.Slice(a, func(i, j int) bool {
		return netCompare(*a[i], *a[j]) == -1
	})
}

// deltaNets returns the changes to turn a into b.
func deltaNets(a, b []*net.IPNet) (add, del []*net.IPNet) {
	add = make([]*net.IPNet, 0, len(b))
	del = make([]*net.IPNet, 0, len(a))
	sortNets(a)
	sortNets(b)

	i := 0
	j := 0
	for i < len(a) && j < len(b) {
		switch netCompare(*a[i], *b[j]) {
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

func excludeIPv6LinkLocal(in []*net.IPNet) (out []*net.IPNet) {
	out = in[:0]
	for _, n := range in {
		if len(n.IP) == 16 && n.IP.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, n)
	}
	return out
}

// ipAdapterUnicastAddressToIPNet converts windows.IpAdapterUnicastAddress to net.IPNet.
func ipAdapterUnicastAddressToIPNet(u *windows.IpAdapterUnicastAddress) *net.IPNet {
	ip := u.Address.IP()
	w := 32
	if ip.To4() == nil {
		w = 128
	}
	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(int(u.OnLinkPrefixLength), w),
	}
}

// unicastIPNets returns all unicast net.IPNet for ifc interface.
func unicastIPNets(ifc *winipcfg.IPAdapterAddresses) []*net.IPNet {
	nets := make([]*net.IPNet, 0)
	for addr := ifc.FirstUnicastAddress; addr != nil; addr = addr.Next {
		nets = append(nets, ipAdapterUnicastAddressToIPNet(addr))
	}
	return nets
}

// syncAddresses incrementally sets the interface's unicast IP addresses,
// doing the minimum number of AddAddresses & DeleteAddress calls.
// This avoids the full FlushAddresses.
//
// Any IPv6 link-local addresses are not deleted.
func syncAddresses(ifc *winipcfg.IPAdapterAddresses, want []*net.IPNet) error {
	var erracc error

	filelogger.WinApiLogger("syncAddresses(%v, %v)\n", ifc, want)

	got := unicastIPNets(ifc)
	add, del := deltaNets(got, want)
	del = excludeIPv6LinkLocal(del)
	for _, a := range del {
		err := ifc.LUID.DeleteIPAddress(*a)
		if err != nil {
			filelogger.WinApiLogger("syncAddresses: ifc.LUID[%v].DeleteIPAddress(%v) ERROR:\n%v\n", ifc.LUID, a,
				err)
			erracc = err
		} else {
			filelogger.WinApiLogger("syncAddresses: ifc.LUID[%v].DeleteIPAddress(%v) SUCCESS\n",	ifc.LUID, a)
		}
	}

	for _, a := range add {
		err := ifc.LUID.AddIPAddress(*a)
		if err != nil {
			filelogger.WinApiLogger("syncAddresses: ifc.LUID[%v].AddIPAddress(%v) ERROR:\n%v\n", ifc.LUID, a,
				err)
			erracc = err
		} else {
			filelogger.WinApiLogger("syncAddresses: ifc.LUID[%v].AddIPAddress(%v) SUCCESS:\n%v\n", ifc.LUID, a)
		}
	}

	return erracc
}

func routeDataCompare(a, b *winipcfg.RouteData) int {
	v := bytes.Compare(a.Destination.IP, b.Destination.IP)
	if v != 0 {
		return v
	}

	// Narrower masks first
	v = bytes.Compare(a.Destination.Mask, b.Destination.Mask)
	if v != 0 {
		return -v
	}

	// No nexthop before non-empty nexthop
	v = bytes.Compare(a.NextHop, b.NextHop)
	if v != 0 {
		return v
	}

	// Lower metrics first
	if a.Metric < b.Metric {
		return -1
	} else if a.Metric > b.Metric {
		return 1
	}

	return 0
}

func sortRouteData(a []*winipcfg.RouteData) {
	sort.Slice(a, func(i, j int) bool {
		return routeDataCompare(a[i], a[j]) < 0
	})
}

func deltaRouteData(a, b []*winipcfg.RouteData) (add, del []*winipcfg.RouteData) {
	add = make([]*winipcfg.RouteData, 0, len(b))
	del = make([]*winipcfg.RouteData, 0, len(a))
	sortRouteData(a)
	sortRouteData(b)

	i := 0
	j := 0
	for i < len(a) && j < len(b) {
		switch routeDataCompare(a[i], b[j]) {
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
	filelogger.WinApiLogger("getInterfaceRoutes(%v, %v)\n", ifc, family)
	routes, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		filelogger.WinApiLogger("getInterfaceRoutes: winipcfg.GetIPForwardTable2(%v) ERROR:\n%v\n", family, err)
		return nil, err
	}
	filelogger.WinApiLogger("getInterfaceRoutes: winipcfg.GetIPForwardTable2(%v) SUCCESS:\n%v\n", family, routes)
	for i := range routes {
		if routes[i].InterfaceLUID == ifc.LUID {
			matches = append(matches, &routes[i])
		}
	}
	return
}

// syncRoutes incrementally sets multiples routes on an interface.
// This avoids a full ifc.FlushRoutes call.
func syncRoutes(ifc *winipcfg.IPAdapterAddresses, want []*winipcfg.RouteData) error {
	filelogger.WinApiLogger("syncRoutes(%v, %v)\n", ifc, want)
	routes, err := getInterfaceRoutes(ifc, windows.AF_INET)
	if err != nil {
		return err
	}

	got := make([]*winipcfg.RouteData, 0, len(routes))
	for _, r := range routes {
		got = append(got, &winipcfg.RouteData{
			Destination: r.DestinationPrefix.IPNet(),
			NextHop:     r.NextHop.IP(),
			Metric:      r.Metric,
		})
	}

	add, del := deltaRouteData(got, want)

	var errs []error
	for _, a := range del {
		err := ifc.LUID.DeleteRoute(a.Destination, a.NextHop)
		if err != nil {
			filelogger.WinApiLogger("syncRoutes: ifc.LUID[%v].DeleteRoute(%v, %v) ERROR:\n%v\n", ifc.LUID,
				a.Destination, a.NextHop, err)
			dstStr := a.Destination.String()
			if dstStr == "169.254.255.255/32" {
				// Issue 785. Ignore these routes
				// failing to delete. Harmless.
				continue
			}
			errs = append(errs, fmt.Errorf("deleting route %v: %w", dstStr, err))
		} else {
			filelogger.WinApiLogger("syncRoutes: ifc.LUID[%v].DeleteRoute(%v, %v) SUCCESS:\n%v\n", ifc.LUID,
				a.Destination, a.NextHop)
		}
	}

	for _, a := range add {
		err := ifc.LUID.AddRoute(a.Destination, a.NextHop, a.Metric)
		if err != nil {
			filelogger.WinApiLogger("syncRoutes: ifc.LUID[%v].AddRoute(%v, %v, %v) ERROR:\n%v\n", ifc.LUID,
				a.Destination, a.NextHop, a.Metric, err)
			errs = append(errs, fmt.Errorf("adding route %v: %w", &a.Destination, err))
		} else {
			filelogger.WinApiLogger("syncRoutes: ifc.LUID[%v].AddRoute(%v, %v, %v) SUCCESS:\n%v\n", ifc.LUID,
				a.Destination, a.NextHop, a.Metric)
		}
	}

	return multierror.New(errs)
}

func getIpInterface(iface *winipcfg.IPAdapterAddresses, family winipcfg.AddressFamily) (*winipcfg.MibIPInterfaceRow, error) {
	filelogger.WinApiLogger("getIpInterface(%v, %v)\n", iface, family)
	logTheCurrentState(iface, family)
	ipif, err := iface.LUID.IPInterface(family)
	if err == nil {
		filelogger.WinApiLogger("getIpInterface: iface.LUID[%v].IPInterface(%v) SUCCESS:\n%v\n", iface.LUID, family,
			ipif)
		return ipif, nil
	}
	if family == windows.AF_INET {
		filelogger.WinApiLogger("getIpInterface: THE ERROR!\n")
	}
	filelogger.WinApiLogger("getIpInterface: iface.LUID[%v].IPInterface(%v) ERROR:\n%v\n", iface.LUID, family,
		err)

	ifs, err2 := winipcfg.GetIPInterfaceTable(family)
	if err2 != nil {
		filelogger.WinApiLogger("getIpInterface: winipcfg.GetIPInterfaceTable(%v) ERROR:\n%v\n", family, err2)
	} else if ifs == nil {
		filelogger.WinApiLogger("getIpInterface: winipcfg.GetIPInterfaceTable(%v) NIL\n", family)
	} else {
		filelogger.WinApiLogger("getIpInterface: winipcfg.GetIPInterfaceTable(%v) SUCCESS:\n%v\n", family, ifs)
		for i := range ifs {
			if ifs[i].InterfaceLUID == iface.LUID {
				filelogger.WinApiLogger("getIpInterface: fallback success:\n%v\n", &ifs[i])
				return &ifs[i], nil
			}
		}
	}

	ifs, err2 = winipcfg.GetIPInterfaceTable(windows.AF_UNSPEC)
	if err2 != nil {
		filelogger.WinApiLogger("getIpInterface: winipcfg.GetIPInterfaceTable(windows.AF_UNSPEC) ERROR:\n%v\n", err2)
	} else if ifs == nil {
		filelogger.WinApiLogger("getIpInterface: winipcfg.GetIPInterfaceTable(windows.AF_UNSPEC) NIL\n")
	} else {
		filelogger.WinApiLogger("getIpInterface: winipcfg.GetIPInterfaceTable(windows.AF_UNSPEC) SUCCESS:\n%v\n", ifs)
		for i := range ifs {
			if ifs[i].InterfaceLUID == iface.LUID {
				filelogger.WinApiLogger("getIpInterface: fallback AF_UNSPEC success (not up though):\n", &ifs[i])
				return &ifs[i], nil
			}
		}
	}

	return nil, err
}

func logTheCurrentState(iface *winipcfg.IPAdapterAddresses, family winipcfg.AddressFamily) {
	filelogger.WinApiLogger("logTheCurrentState(%v, %v); iface.OperStatus = %v\n", iface, family, iface.OperStatus)
	ifc, err := iface.LUID.Interface()
	if err != nil {
		filelogger.WinApiLogger("logTheCurrentState: iface.LUID[%v].Interface() ERROR:\n%v\n", iface.LUID, err)
	} else if ifc == nil {
		filelogger.WinApiLogger("logTheCurrentState: iface.LUID[%v].Interface() NIL\n", iface.LUID)
	} else {
		filelogger.WinApiLogger("logTheCurrentState: iface.LUID[%v].Interface() SUCCESS:\n%v\nifc.OperStatus = %v; ifc.AdminStatus = %v",
			iface.LUID, ifc, ifc.OperStatus, ifc.AdminStatus)
	}
}

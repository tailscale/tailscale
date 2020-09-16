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
	"os"
	"sort"
	"time"

	ole "github.com/go-ole/go-ole"
	winipcfg "github.com/tailscale/winipcfg-go"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
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
	guid := tun.GUID()
	ourLuid, err := winipcfg.InterfaceGuidToLuid(&guid)
	lastMtu := uint32(0)
	if err != nil {
		return nil, err
	}
	doIt := func() error {
		mtu, err := getDefaultRouteMTU()
		if err != nil {
			return err
		}

		if mtu > 0 && (lastMtu == 0 || lastMtu != mtu) {
			iface, err := winipcfg.GetIpInterface(ourLuid, winipcfg.AF_INET)
			if err != nil {
				return err
			}
			iface.NlMtu = mtu - 80
			// If the TUN device was created with a smaller MTU,
			// though, such as 1280, we don't want to go bigger than
			// configured. (See the comment on minimalMTU in the
			// wgengine package.)
			if min, err := tun.MTU(); err == nil && min < int(iface.NlMtu) {
				iface.NlMtu = uint32(min)
			}
			if iface.NlMtu < 576 {
				iface.NlMtu = 576
			}
			err = iface.Set()
			if err != nil {
				return err
			}
			tun.ForceMTU(int(iface.NlMtu))
			iface, err = winipcfg.GetIpInterface(ourLuid, winipcfg.AF_INET6)
			if err != nil {
				if !isMissingIPv6Err(err) {
					return err
				}
			} else {
				iface.NlMtu = mtu - 80
				if iface.NlMtu < 1280 {
					iface.NlMtu = 1280
				}
				err = iface.Set()
				if err != nil {
					return err
				}
			}
			lastMtu = mtu
		}
		return nil
	}
	err = doIt()
	if err != nil {
		return nil, err
	}
	cb, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.Route) {
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

	routes, err := winipcfg.GetRoutes(winipcfg.AF_INET)
	if err != nil {
		return 0, err
	}
	best := ^uint32(0)
	mtu := uint32(0)
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		routeMTU := mtus[route.InterfaceLuid]
		if routeMTU == 0 {
			continue
		}
		if route.Metric < best {
			best = route.Metric
			mtu = routeMTU
		}
	}

	routes, err = winipcfg.GetRoutes(winipcfg.AF_INET6)
	if err != nil {
		return 0, err
	}
	best = ^uint32(0)
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		routeMTU := mtus[route.InterfaceLuid]
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
func setPrivateNetwork(ifcGUID *windows.GUID) (bool, error) {
	// NLM_NETWORK_CATEGORY values.
	const (
		categoryPublic  = 0
		categoryPrivate = 1
		categoryDomain  = 2
	)
	var c ole.Connection
	if err := c.Initialize(); err != nil {
		return false, fmt.Errorf("c.Initialize: %v", err)
	}
	defer c.Uninitialize()

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

func configureInterface(cfg *Config, tun *tun.NativeTun) error {
	const mtu = 0
	guid := tun.GUID()
	iface, err := winipcfg.InterfaceFromGUID(&guid)
	if err != nil {
		return err
	}

	go func() {
		// It takes a weirdly long time for Windows to notice the
		// new interface has come up. Poll periodically until it
		// does.
		const tries = 20
		for i := 0; i < tries; i++ {
			found, err := setPrivateNetwork(&guid)
			if err != nil {
				log.Printf("setPrivateNetwork(try=%d): %v", i, err)
			} else {
				if found {
					return
				}
				log.Printf("setPrivateNetwork(try=%d): not found", i)
			}
			time.Sleep(1 * time.Second)
		}
		log.Printf("setPrivateNetwork: adapter %v not found after %d tries, giving up", guid, tries)
	}()

	routes := []winipcfg.RouteData{}
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

	err = iface.SyncAddresses(addresses)
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

	var errAcc error
	err = iface.SyncRoutes(deduplicatedRoutes)
	if err != nil && errAcc == nil {
		log.Printf("setroutes: %v", err)
		errAcc = err
	}

	ipif, err := iface.GetIpInterface(winipcfg.AF_INET)
	if err != nil {
		log.Printf("getipif: %v", err)
		return err
	}
	if foundDefault4 {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}
	if mtu > 0 {
		ipif.NlMtu = uint32(mtu)
		tun.ForceMTU(int(ipif.NlMtu))
	}
	err = ipif.Set()
	if err != nil && errAcc == nil {
		errAcc = err
	}

	ipif, err = iface.GetIpInterface(winipcfg.AF_INET6)
	if err != nil {
		if !isMissingIPv6Err(err) {
			return err
		}
	} else {
		if foundDefault6 {
			ipif.UseAutomaticMetric = false
			ipif.Metric = 0
		}
		if mtu > 0 {
			ipif.NlMtu = uint32(mtu)
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

// isMissingIPv6Err reports whether err is due to IPv6 not being enabled on the machine.
//
// It only currently supports the errors returned by winipcfg.Interface.GetIpInterface.
func isMissingIPv6Err(err error) bool {
	if se, ok := err.(*os.SyscallError); ok {
		switch se.Syscall {
		case "iphlpapi.GetIpInterfaceEntry":
			// ERROR_NOT_FOUND from means the address family (IPv6) is not found.
			// (ERROR_FILE_NOT_FOUND means that the interface doesn't exist.)
			// https://docs.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipinterfaceentry
			return se.Err == windows.ERROR_NOT_FOUND
		}
	}
	return false
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

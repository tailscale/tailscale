/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wgengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"time"
	"unsafe"

	ole "github.com/go-ole/go-ole"
	winipcfg "github.com/tailscale/winipcfg-go"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"tailscale.com/wgengine/winnet"
)

const (
	sockoptIP_UNICAST_IF   = 31
	sockoptIPV6_UNICAST_IF = 31
)

func htonl(val uint32) uint32 {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, val)
	return *(*uint32)(unsafe.Pointer(&bytes[0]))
}

func bindSocketRoute(family winipcfg.AddressFamily, device *device.Device, ourLuid uint64, lastLuid *uint64) error {
	routes, err := winipcfg.GetRoutes(family)
	if err != nil {
		return err
	}
	lowestMetric := ^uint32(0)
	index := uint32(0) // Zero is "unspecified", which for IP_UNICAST_IF resets the value, which is what we want.
	luid := uint64(0)  // Hopefully luid zero is unspecified, but hard to find docs saying so.
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 || route.InterfaceLuid == ourLuid {
			continue
		}
		if route.Metric < lowestMetric {
			lowestMetric = route.Metric
			index = route.InterfaceIndex
			luid = route.InterfaceLuid
		}
	}
	if luid == *lastLuid {
		return nil
	}
	*lastLuid = luid
	if false {
		// TODO(apenwarr): doesn't work with magic socket yet.
		if family == winipcfg.AF_INET {
			return device.BindSocketToInterface4(index, false)
		} else if family == winipcfg.AF_INET6 {
			return device.BindSocketToInterface6(index, false)
		}
	} else {
		log.Printf("WARNING: skipping windows socket binding.\n")
	}
	return nil
}

func MonitorDefaultRoutes(device *device.Device, autoMTU bool, tun *tun.NativeTun) (*winipcfg.RouteChangeCallback, error) {
	guid := tun.GUID()
	ourLuid, err := winipcfg.InterfaceGuidToLuid(&guid)
	lastLuid4 := uint64(0)
	lastLuid6 := uint64(0)
	lastMtu := uint32(0)
	if err != nil {
		return nil, err
	}
	doIt := func() error {
		err = bindSocketRoute(winipcfg.AF_INET, device, ourLuid, &lastLuid4)
		if err != nil {
			return err
		}
		err = bindSocketRoute(winipcfg.AF_INET6, device, ourLuid, &lastLuid6)
		if err != nil {
			return err
		}
		if !autoMTU {
			return nil
		}
		mtu := uint32(0)
		if lastLuid4 != 0 {
			iface, err := winipcfg.InterfaceFromLUID(lastLuid4)
			if err != nil {
				return err
			}
			if iface.Mtu > 0 {
				mtu = iface.Mtu
			}
		}
		if lastLuid6 != 0 {
			iface, err := winipcfg.InterfaceFromLUID(lastLuid6)
			if err != nil {
				return err
			}
			if iface.Mtu > 0 && iface.Mtu < mtu {
				mtu = iface.Mtu
			}
		}
		if mtu > 0 && (lastMtu == 0 || lastMtu != mtu) {
			iface, err := winipcfg.GetIpInterface(ourLuid, winipcfg.AF_INET)
			if err != nil {
				return err
			}
			iface.NlMtu = mtu - 80
			if iface.NlMtu < 576 {
				iface.NlMtu = 576
			}
			err = iface.Set()
			if err != nil {
				return err
			}
			tun.ForceMTU(int(iface.NlMtu)) //TODO: it sort of breaks the model with v6 mtu and v4 mtu being different. Just set v4 one for now.
			iface, err = winipcfg.GetIpInterface(ourLuid, winipcfg.AF_INET6)
			if err != nil {
				return err
			}
			iface.NlMtu = mtu - 80
			if iface.NlMtu < 1280 {
				iface.NlMtu = 1280
			}
			err = iface.Set()
			if err != nil {
				return err
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

func setDNSDomains(g windows.GUID, dnsDomains []string) {
	gs := g.String()
	log.Printf("setDNSDomains(%v) guid=%v\n", dnsDomains, gs)
	p := `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` + gs
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ|registry.SET_VALUE)
	if err != nil {
		log.Printf("setDNSDomains(%v): open: %v\n", p, err)
		return
	}
	defer key.Close()

	// Windows only supports a single per-interface DNS domain.
	dom := ""
	if len(dnsDomains) > 0 {
		dom = dnsDomains[0]
	}
	err = key.SetStringValue("Domain", dom)
	if err != nil {
		log.Printf("setDNSDomains(%v): SetStringValue: %v\n", p, err)
	}
}

func setFirewall(ifcGUID *windows.GUID) (bool, error) {
	c := ole.Connection{}
	err := c.Initialize()
	if err != nil {
		panic(err)
	}
	defer c.Uninitialize()

	m, err := winnet.NewNetworkListManager(&c)
	if err != nil {
		panic(err)
	}
	defer m.Release()

	cl, err := m.GetNetworkConnections()
	if err != nil {
		panic(err)
	}
	defer cl.Release()

	for _, nco := range cl {
		aid, err := nco.GetAdapterId()
		if err != nil {
			panic(err)
		}
		if aid != ifcGUID.String() {
			log.Printf("skipping adapter id: %v\n", aid)
			continue
		}
		log.Printf("found! adapter id: %v\n", aid)

		n, err := nco.GetNetwork()
		if err != nil {
			return false, fmt.Errorf("GetNetwork: %v", err)
		}
		defer n.Release()

		cat, err := n.GetCategory()
		if err != nil {
			return false, fmt.Errorf("GetCategory: %v", err)
		}

		if cat == 0 {
			err = n.SetCategory(1)
			if err != nil {
				return false, fmt.Errorf("SetCategory: %v", err)
			}
		} else {
			log.Printf("setFirewall: already category %v\n", cat)
		}

		return true, nil
	}

	return false, nil
}

func ConfigureInterface(m *wgcfg.Config, tun *tun.NativeTun, dns []net.IP, dnsDomains []string) error {
	const mtu = 0
	guid := tun.GUID()
	log.Printf("wintun GUID is %v\n", guid)
	iface, err := winipcfg.InterfaceFromGUID(&guid)
	if err != nil {
		return err
	}

	go func() {
		// It takes a weirdly long time for Windows to notice the
		// new interface has come up. Poll periodically until it
		// does.
		for i := 0; i < 20; i++ {
			found, err := setFirewall(&guid)
			if err != nil {
				log.Printf("setFirewall: %v\n", err)
				// fall through anyway, this isn't fatal.
			}
			if found {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}()

	setDNSDomains(guid, dnsDomains)

	routes := []winipcfg.RouteData{}
	var firstGateway4 *net.IP
	var firstGateway6 *net.IP
	addresses := make([]*net.IPNet, len(m.Interface.Addresses))
	for i, addr := range m.Interface.Addresses {
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
	for _, peer := range m.Peers {
		for _, allowedip := range peer.AllowedIPs {
			if (allowedip.IP.Is4() && firstGateway4 == nil) || (allowedip.IP.Is6() && firstGateway6 == nil) {
				return errors.New("Due to a Windows limitation, one cannot have interface routes without an interface address")
			}

			ipn := allowedip.IPNet()
			var gateway net.IP
			if allowedip.IP.Is4() {
				gateway = *firstGateway4
			} else if allowedip.IP.Is6() {
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
			if allowedip.IP.Is4() {
				if allowedip.Mask == 0 {
					foundDefault4 = true
				}
				r.NextHop = *firstGateway4
			} else if allowedip.IP.Is6() {
				if allowedip.Mask == 0 {
					foundDefault6 = true
				}
				r.NextHop = *firstGateway6
			}
			routes = append(routes, r)
		}
	}

	err = iface.SetAddresses(addresses)
	if err != nil {
		return err
	}

	sort.Slice(routes, func(i, j int) bool {
		return (bytes.Compare(routes[i].Destination.IP, routes[j].Destination.IP) == -1 ||
			// Narrower masks first
			bytes.Compare(routes[i].Destination.Mask, routes[j].Destination.Mask) == 1 ||
			// No nexthop before non-empty nexthop
			bytes.Compare(routes[i].NextHop, routes[j].NextHop) == -1 ||
			// Lower metrics first
			routes[i].Metric < routes[j].Metric)
	})

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
	log.Printf("routes: %v\n", routes)

	var errAcc error
	err = iface.SetRoutes(deduplicatedRoutes)
	if err != nil && errAcc == nil {
		log.Printf("setroutes: %v\n", err)
		errAcc = err
	}

	err = iface.SetDNS(dns)
	if err != nil && errAcc == nil {
		log.Printf("setdns: %v\n", err)
		errAcc = err
	}

	ipif, err := iface.GetIpInterface(winipcfg.AF_INET)
	if err != nil {
		log.Printf("getipif: %v\n", err)
		return err
	}
	log.Printf("foundDefault4: %v\n", foundDefault4)
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
		return err
	}
	if err != nil && errAcc == nil {
		errAcc = err
	}
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

	return errAcc
}

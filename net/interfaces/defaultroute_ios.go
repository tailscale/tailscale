// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios

package interfaces

import (
	"log"

	"tailscale.com/syncs"
)

var (
	lastKnownDefaultRouteIfName syncs.AtomicValue[string]
)

// UpdateLastKnownDefaultRouteInterface is called by ipn-go-bridge in the iOS app when
// our NWPathMonitor instance detects a network path transition.
func UpdateLastKnownDefaultRouteInterface(ifName string) {
	if ifName == "" {
		return
	}
	lastKnownDefaultRouteIfName.Store(ifName)
	log.Printf("defaultroute_ios: update from Swift, ifName = %s", ifName)
}

func defaultRoute() (d DefaultRouteDetails, err error) {
	// We cannot rely on the delegated interface data on iOS. The NetworkExtension framework
	// seems to set the delegate interface only once, upon the *creation* of the VPN tunnel.
	// If a network transition (e.g. from Wi-Fi to Cellular) happens while the tunnel is
	// connected, it will be ignored and we will still try to set Wi-Fi as the default route
	// because the delegated interface is not updated by the NetworkExtension framework.
	//
	// We work around this on the Swift side with a NWPathMonitor instance that observes
	// the interface name of the first currently satisfied network path. Our Swift code will
	// call into `UpdateLastKnownDefaultRouteInterface`, so we can rely on that when it is set.
	//
	// If for any reason the Swift machinery didn't work and we don't get any updates, here
	// we also have some fallback logic: we try finding a hardcoded Wi-Fi interface called en0.
	// If en0 is down, we fall back to cellular (pdp_ip0) as a last resort. This doesn't handle
	// all edge cases like USB-Ethernet adapters or multiple Ethernet interfaces, but is good
	// enough to ensure connectivity isn't broken.

	// Start by getting all available interfaces.
	interfaces, err := netInterfaces()
	if err != nil {
		log.Printf("defaultroute_ios: could not get interfaces: %v", err)
		return d, ErrNoGatewayIndexFound
	}

	getInterfaceByName := func(name string) *Interface {
		for _, ifc := range interfaces {
			if ifc.Name != name {
				continue
			}

			if !ifc.IsUp() {
				log.Println("defaultroute_ios: %s is down", name)
				return nil
			}

			addrs, _ := ifc.Addrs()
			if len(addrs) == 0 {
				log.Println("defaultroute_ios: %s has no addresses", name)
				return nil
			}
			return &ifc
		}
		return nil
	}

	// Did Swift set lastKnownDefaultRouteInterface? If so, we should use it and don't bother
	// with anything else. However, for sanity, do check whether Swift gave us with an interface
	// that exists, is up, and has an address.
	if swiftIfName := lastKnownDefaultRouteIfName.Load(); swiftIfName != "" {
		ifc := getInterfaceByName(swiftIfName)
		if ifc != nil {
			log.Printf("defaultroute_ios: using %s (provided by Swift)", ifc.Name)
			d.InterfaceName = ifc.Name
			d.InterfaceIndex = ifc.Index
			return d, nil
		}
	}

	// Start of our fallback logic if Swift didn't give us an interface name, or gave us an invalid
	// one.
	// We start by attempting to use the Wi-Fi interface, which on iPhone is always called en0.
	enZeroIf := getInterfaceByName("en0")
	if enZeroIf != nil {
		log.Println("defaultroute_ios: using en0 (fallback)")
		d.InterfaceName = enZeroIf.Name
		d.InterfaceIndex = enZeroIf.Index
		return d, nil
	}

	// Did it not work? Let's try with Cellular (pdp_ip0).
	cellIf := getInterfaceByName("pdp_ip0")
	if cellIf != nil {
		log.Println("defaultroute_ios: using pdp_ip0 (fallback)")
		d.InterfaceName = cellIf.Name
		d.InterfaceIndex = cellIf.Index
		return d, nil
	}

	log.Println("defaultroute_ios: no running interfaces available")
	return d, ErrNoGatewayIndexFound
}

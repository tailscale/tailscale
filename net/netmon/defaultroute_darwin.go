// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || ios

package netmon

import (
	"errors"
	"fmt"
	"log"
	"net"

	"tailscale.com/syncs"
)

var (
	lastKnownDefaultRouteIfName syncs.AtomicValue[string]
)

// UpdateLastKnownDefaultRouteInterface is called by ipn-go-bridge from apple network extensions when
// our NWPathMonitor instance detects a network path transition.
func UpdateLastKnownDefaultRouteInterface(ifName string) {
	if ifName == "" {
		return
	}
	if old := lastKnownDefaultRouteIfName.Swap(ifName); old != ifName {
		interfaces, err := netInterfaces()
		if err != nil {
			log.Printf("defaultroute_darwin: UpdateLastKnownDefaultRouteInterface could not get interfaces: %v", err)
			return
		}

		netif, err := getInterfaceByName(ifName, interfaces)
		if err != nil {
			log.Printf("defaultroute_darwin: UpdateLastKnownDefaultRouteInterface could not find interface index for %s: %v", ifName, err)
			return
		}

		log.Printf("defaultroute_darwin: updated last known default if from OS, ifName = %s index: %d (was %s)", ifName, netif.Index, old)
	}
}

func defaultRoute() (d DefaultRouteDetails, err error) {
	// We cannot rely on the delegated interface data on darwin. The NetworkExtension framework
	// seems to set the delegate interface only once, upon the *creation* of the VPN tunnel.
	// If a network transition (e.g. from Wi-Fi to Cellular) happens while the tunnel is
	// connected, it will be ignored and we will still try to set Wi-Fi as the default route
	// because the delegated interface is not updated by the NetworkExtension framework.
	//
	// We work around this on the Swift side with a NWPathMonitor instance that observes
	// the interface name of the first currently satisfied network path. Our Swift code will
	// call into `UpdateLastKnownDefaultRouteInterface`, so we can rely on that when it is set.
	//
	// If for any reason the Swift machinery didn't work and we don't get any updates, we will
	// fallback to the BSD logic.
	osRoute, osRouteErr := OSDefaultRoute()
	if osRouteErr == nil {
		// If we got a valid interface from the OS, use it.
		d.InterfaceName = osRoute.InterfaceName
		d.InterfaceIndex = osRoute.InterfaceIndex
		return d, nil
	}

	// Fallback to the BSD logic
	idx, err := DefaultRouteInterfaceIndex()
	if err != nil {
		return d, err
	}
	iface, err := net.InterfaceByIndex(idx)
	if err != nil {
		return d, err
	}
	d.InterfaceName = iface.Name
	d.InterfaceIndex = idx
	return d, nil
}

// OSDefaultRoute returns the DefaultRouteDetails for the default interface as provided by the OS
// via UpdateLastKnownDefaultRouteInterface.  If UpdateLastKnownDefaultRouteInterface has not been called,
// the interface name is not valid, or we cannot find its index, an error is returned.
func OSDefaultRoute() (d DefaultRouteDetails, err error) {

	// Did Swift set lastKnownDefaultRouteInterface? If so, we should use it and don't bother
	// with anything else. However, for sanity, do check whether Swift gave us with an interface
	// that exists, is up, and has an address and is not the tunnel itself.
	if swiftIfName := lastKnownDefaultRouteIfName.Load(); swiftIfName != "" {
		// Start by getting all available interfaces.
		interfaces, err := netInterfaces()
		if err != nil {
			log.Printf("defaultroute_darwin: could not get interfaces: %v", err)
			return d, err
		}

		if ifc, err := getInterfaceByName(swiftIfName, interfaces); err == nil {
			d.InterfaceName = ifc.Name
			d.InterfaceIndex = ifc.Index
			return d, nil
		}
	}
	err = errors.New("no os provided default route interface found")
	return d, err
}

func getInterfaceByName(name string, interfaces []Interface) (*Interface, error) {
	for _, ifc := range interfaces {
		if ifc.Name != name {
			continue
		}

		if !ifc.IsUp() {
			return nil, fmt.Errorf("defaultroute_darwin: %s is down", name)
		}

		addrs, _ := ifc.Addrs()
		if len(addrs) == 0 {
			return nil, fmt.Errorf("defaultroute_darwin: %s has no addresses", name)
		}
		return &ifc, nil
	}
	return nil, errors.New("no interfaces found")
}

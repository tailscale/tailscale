// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || ios

package netmon

import (
	"log"
	"net"

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
	if old := lastKnownDefaultRouteIfName.Swap(ifName); old != ifName {
		log.Printf("defaultroute_darwin: update from Swift, ifName = %s (was %s)", ifName, old)
	}
}

// findOpenVPNInterface looks for an OpenVPN interface and returns it if
// found. The two key identifying factors for on Macs are
//
// 1) the interface is named utun*; and
// 2) two pseudo-default half routes are installed, 0/1 and 128.0/1.
//
// so we look to see if we detect both those conditions.
func findOpenVPNInterface() (*Interface, error) {
	interfaces, err := netInterfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if !iface.IsUp() {
			continue
		}

		if isOpenVPNInterface(iface.Interface) {
			// Verify it has an address
			addrs, _ := iface.Addrs()
			if len(addrs) > 0 {
				log.Printf("defaultroute_darwin: found OpenVPN interface: %s", iface.Name)
				return &iface, nil
			}
		}
	}

	return nil, nil // No OpenVPN interface found
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

	// Start by getting all available interfaces.
	interfaces, err := netInterfaces()
	if err != nil {
		log.Printf("defaultroute_darwin: could not get interfaces: %v", err)
		return d, ErrNoGatewayIndexFound
	}

	// If we detect an OpenVPN interface, prefer it over other interfaces This
	// ensures Tailscale routes over the OpenVPN tunnel when present
	if openVPNIface, err := findOpenVPNInterface(); err == nil && openVPNIface != nil {
		log.Printf("defaultroute_darwin: preferring OpenVPN interface: %s", openVPNIface.Name)
		d.InterfaceName = openVPNIface.Name
		d.InterfaceIndex = openVPNIface.Index
		return d, nil
	}

	getInterfaceByName := func(name string) *Interface {
		for _, ifc := range interfaces {
			if ifc.Name != name {
				continue
			}

			if !ifc.IsUp() {
				log.Printf("defaultroute_darwin: %s is down", name)
				return nil
			}

			addrs, _ := ifc.Addrs()
			if len(addrs) == 0 {
				log.Printf("defaultroute_darwin: %s has no addresses", name)
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
			d.InterfaceName = ifc.Name
			d.InterfaceIndex = ifc.Index
			return d, nil
		}
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

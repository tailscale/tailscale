// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tswg

import (
	"errors"
	"fmt"

	"github.com/tailscale/netlink"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

// ErrModuleNotLoaded is returned by NewTailscaleDevice when the tswg kernel
// module isn't loaded.
var ErrModuleNotLoaded = errors.New("tswg: kernel module not loaded")

// NewTailscaleDevice creates the tswg network device named name (normally
// "tailscale0") for tailscaled to use as its kernel data plane, replacing
// any existing tswg device of that name, and sets its MTU.
//
// It returns a tun.Device for the rest of tailscaled (the engine, router
// and so on) to hold in place of a TUN device. It reports name as its
// name, so that the router configures addresses and routes on the tswg
// device, but its packets are those of a real TUN device, named name plus
// "-svc", for the packets tailscaled answers itself: the router sends
// routes to the Tailscale service IPs (100.100.100.100 and
// fd7a:115c:a1e0::53, for MagicDNS and so on) there, and netstack answers
// them as in TUN mode. Nothing else is routed to it.
func NewTailscaleDevice(name string, mtu int) (tun.Device, error) {
	if !ModuleLoaded() {
		return nil, ErrModuleNotLoaded
	}
	svcName := name + "-svc"
	if len(svcName) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("tswg: device name %q too long for its service TUN %q", name, svcName)
	}
	if link, err := netlink.LinkByName(name); err == nil {
		if link.Type() != LinkType {
			return nil, fmt.Errorf("tswg: existing interface %q has type %q, not %q", name, link.Type(), LinkType)
		}
		// Start from a clean device rather than inheriting peers and
		// sockets from a previous tailscaled.
		if err := netlink.LinkDel(link); err != nil {
			return nil, fmt.Errorf("tswg: deleting stale %q: %w", name, err)
		}
	}
	if err := AddLink(name); err != nil {
		return nil, err
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		DeleteLink(name)
		return nil, fmt.Errorf("tswg: setting MTU of %q: %w", name, err)
	}
	svc, err := tun.CreateTUN(svcName, mtu)
	if err != nil {
		DeleteLink(name)
		return nil, fmt.Errorf("tswg: creating service TUN %q: %w", svcName, err)
	}
	// The router brings up only the device it's told the name of.
	svcLink, err := netlink.LinkByName(svcName)
	if err == nil {
		err = netlink.LinkSetUp(svcLink)
	}
	if err != nil {
		svc.Close()
		DeleteLink(name)
		return nil, fmt.Errorf("tswg: bringing up service TUN %q: %w", svcName, err)
	}
	return &serviceTUN{Device: svc, name: name, svcName: svcName}, nil
}

// serviceTUN is the tun.Device that NewTailscaleDevice returns: the real
// TUN device svcName, reporting the tswg device's name.
//
// It deliberately embeds only the tun.Device interface, so that optional
// methods of the underlying device aren't promoted.
type serviceTUN struct {
	tun.Device
	name    string
	svcName string
}

func (t *serviceTUN) Name() (string, error) { return t.name, nil }

// ServiceTUNName returns the name of the real TUN device, for the router;
// see NewTailscaleDevice.
func (t *serviceTUN) ServiceTUNName() string { return t.svcName }

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tswg

import (
	"errors"
	"fmt"

	"github.com/tailscale/netlink"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/tstun"
)

// ErrModuleNotLoaded is returned by NewTailscaleDevice when the tswg kernel
// module isn't loaded.
var ErrModuleNotLoaded = errors.New("tswg: kernel module not loaded")

// NewTailscaleDevice creates the tswg network device named name (normally
// "tailscale0") for tailscaled to use as its kernel data plane, replacing
// any existing tswg device of that name, and sets its MTU.
//
// It returns a tun.Device for the rest of tailscaled (the engine, router
// and so on) to hold in place of a TUN device. It carries no packets; it
// only reports name as its name, so that the router configures addresses
// and routes on the tswg device.
func NewTailscaleDevice(name string, mtu int) (tun.Device, error) {
	if !ModuleLoaded() {
		return nil, ErrModuleNotLoaded
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
	return &nameOnlyTUN{Device: tstun.NewFake(), name: name}, nil
}

// nameOnlyTUN is a fake tun.Device that reports a given name.
//
// It deliberately embeds only the tun.Device interface, so that optional
// methods of the underlying fake (such as IsFakeTun, which other code uses
// to detect userspace networking mode) aren't promoted.
type nameOnlyTUN struct {
	tun.Device
	name string
}

func (t *nameOnlyTUN) Name() (string, error) { return t.name, nil }

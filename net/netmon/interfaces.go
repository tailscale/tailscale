// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"errors"
	"net"

	"tailscale.com/syncs"
)

type ifProps struct {
	mu    syncs.Mutex
	name  string // interface name, if known/set
	index int    // interface index, if known/set
}

// tsIfProps tracks the properties (name and index) of the tailscale interface.
// There is only one tailscale interface per tailscaled instance.
var tsIfProps ifProps

func (p *ifProps) tsIfName() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.name
}

func (p *ifProps) tsIfIndex() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.index
}

func (p *ifProps) set(ifName string, ifIndex int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.name = ifName
	p.index = ifIndex
}

// TODO (barnstar): This doesn't need the Monitor receiver anymore but we're
// keeping it for API compatibility to avoid a breaking change.  This can be
// removed when the various clients have switched to SetTailscaleInterfaceProps
func (m *Monitor) SetTailscaleInterfaceName(ifName string) {
	SetTailscaleInterfaceProps(ifName, 0)
}

// SetTailscaleInterfaceProps sets the name of the Tailscale interface and
// its index for use by various listeners/dialers.  If the index is zero,
// an attempt will be made to look it up by name.  This makes no attempt
// to validate that the interface exists at the time of calling.
//
// If this method is called, it is the responsibility of the caller to
// update the interface name and index if they change.
//
// This should be called as early as possible during tailscaled startup.
func SetTailscaleInterfaceProps(ifName string, ifIndex int) {
	if ifIndex != 0 {
		tsIfProps.set(ifName, ifIndex)
		return
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, iface := range ifaces {
		if iface.Name == ifName {
			ifIndex = iface.Index
			break
		}
	}

	tsIfProps.set(ifName, ifIndex)
}

// TailscaleInterfaceName returns the name of the Tailscale interface.
// For example, "tailscale0", "tun0", "utun3", etc or an error if unset.
//
// Callers must handle errors, as the Tailscale interface
// name may not be set in some environments.
func TailscaleInterfaceName() (string, error) {
	name := tsIfProps.tsIfName()
	if name == "" {
		return "", errors.New("Tailscale interface name not set")
	}
	return name, nil
}

// TailscaleInterfaceIndex returns the index of the Tailscale interface or
// an error if unset.
//
// Callers must handle errors, as the Tailscale interface
// index may not be set in some environments.
func TailscaleInterfaceIndex() (int, error) {
	index := tsIfProps.tsIfIndex()
	if index == 0 {
		return 0, errors.New("Tailscale interface index not set")
	}
	return index, nil
}

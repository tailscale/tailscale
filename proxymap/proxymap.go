// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package proxymap contains a mapping table for ephemeral localhost ports used
// by tailscaled on behalf of remote Tailscale IPs for proxied connections.
package proxymap

import (
	"net/netip"
	"sync"
	"time"

	"tailscale.com/util/mak"
)

// Mapper tracks which localhost ip:ports correspond to which remote Tailscale
// IPs for connections proxied by tailscaled.
//
// This is then used (via the WhoIsIPPort method) by localhost applications to
// ask tailscaled (via the LocalAPI WhoIs method) the Tailscale identity that a
// given localhost:port corresponds to.
type Mapper struct {
	mu sync.Mutex
	m  map[netip.AddrPort]netip.Addr
}

// RegisterIPPortIdentity registers a given node (identified by its
// Tailscale IP) as temporarily having the given IP:port for whois lookups.
// The IP:port is generally a localhost IP and an ephemeral port, used
// while proxying connections to localhost when tailscaled is running
// in netstack mode.
func (m *Mapper) RegisterIPPortIdentity(ipport netip.AddrPort, tsIP netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mak.Set(&m.m, ipport, tsIP)
}

// UnregisterIPPortIdentity removes a temporary IP:port registration
// made previously by RegisterIPPortIdentity.
func (m *Mapper) UnregisterIPPortIdentity(ipport netip.AddrPort) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, ipport)
}

var whoIsSleeps = [...]time.Duration{
	0,
	10 * time.Millisecond,
	20 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
}

// WhoIsIPPort looks up an IP:port in the temporary registrations,
// and returns a matching Tailscale IP, if it exists.
func (m *Mapper) WhoIsIPPort(ipport netip.AddrPort) (tsIP netip.Addr, ok bool) {
	// We currently have a registration race,
	// https://github.com/tailscale/tailscale/issues/1616,
	// so loop a few times for now waiting for the registration
	// to appear.
	// TODO(bradfitz,namansood): remove this once #1616 is fixed.
	for _, d := range whoIsSleeps {
		time.Sleep(d)
		m.mu.Lock()
		tsIP, ok = m.m[ipport]
		m.mu.Unlock()
		if ok {
			return tsIP, true
		}
	}
	return tsIP, false
}

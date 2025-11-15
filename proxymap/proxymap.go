// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package proxymap contains a mapping table for ephemeral localhost ports used
// by tailscaled on behalf of remote Tailscale IPs for proxied connections.
package proxymap

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"tailscale.com/syncs"
	"tailscale.com/util/mak"
)

// Mapper tracks which localhost ip:ports correspond to which remote Tailscale
// IPs for connections proxied by tailscaled.
//
// This is then used (via the WhoIsIPPort method) by localhost applications to
// ask tailscaled (via the LocalAPI WhoIs method) the Tailscale identity that a
// given localhost:port corresponds to.
type Mapper struct {
	mu syncs.Mutex

	// m holds the mapping from localhost IP:ports to Tailscale IPs. It is
	// keyed first by the protocol ("tcp" or "udp"), then by the IP:port.
	//
	// +checklocks:mu
	m map[mappingKey]netip.Addr
}

// String returns a human-readable representation of the current mappings.
func (m *Mapper) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.m) == 0 {
		return "no mappings"
	}
	var sb strings.Builder
	for k, v := range m.m {
		fmt.Fprintf(&sb, "%v/%v=>%v\n", k.proto, k.ap, v)
	}
	return sb.String()
}

type mappingKey struct {
	proto string
	ap    netip.AddrPort
}

// RegisterIPPortIdentity registers a given node (identified by its
// Tailscale IP) as temporarily having the given IP:port for whois lookups.
//
// The IP:port is generally a localhost IP and an ephemeral port, used
// while proxying connections to localhost when tailscaled is running
// in netstack mode.
//
// The proto is the network protocol that is being proxied; it must be "tcp" or
// "udp" (not e.g. "tcp4", "udp6", etc.)
func (m *Mapper) RegisterIPPortIdentity(proto string, ipport netip.AddrPort, tsIP netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := mappingKey{proto, ipport}
	if v, ok := m.m[k]; ok {
		return fmt.Errorf("proxymap: RegisterIPPortIdentity: already registered: %v/%v=>%v", k.proto, k.ap, v)
	}
	mak.Set(&m.m, k, tsIP)
	return nil
}

// UnregisterIPPortIdentity removes a temporary IP:port registration
// made previously by RegisterIPPortIdentity.
func (m *Mapper) UnregisterIPPortIdentity(proto string, ipport netip.AddrPort) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := mappingKey{proto, ipport}
	delete(m.m, k) // safe to delete from a nil map
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
func (m *Mapper) WhoIsIPPort(proto string, ipport netip.AddrPort) (tsIP netip.Addr, ok bool) {
	// We currently have a registration race,
	// https://github.com/tailscale/tailscale/issues/1616,
	// so loop a few times for now waiting for the registration
	// to appear.
	// TODO(bradfitz,namansood): remove this once #1616 is fixed.
	k := mappingKey{proto, ipport}
	for _, d := range whoIsSleeps {
		time.Sleep(d)
		m.mu.Lock()
		tsIP, ok := m.m[k]
		m.mu.Unlock()
		if ok {
			return tsIP, true
		}
	}
	return tsIP, false
}

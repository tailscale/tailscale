// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsdial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// dnsMap maps MagicDNS names (both base + FQDN) to their first IP.
// It must not be mutated once created.
//
// Example keys are "foo.domain.tld.beta.tailscale.net" and "foo",
// both without trailing dots, and both always lowercase.
type dnsMap map[string]netip.Addr

// canonMapKey canonicalizes its input s to be a dnsMap map key.
func canonMapKey(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// errUnresolved is a sentinel error returned by dnsMap.resolveMemory.
var errUnresolved = errors.New("address well formed but not resolved")

func splitHostPort(addr string) (host string, port uint16, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port16, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in address %q", addr)
	}
	return host, uint16(port16), nil
}

// Resolve resolves addr into an IP:port using first the MagicDNS contents
// of m, else using the system resolver.
//
// The error is [exactly] errUnresolved if the addr is a name that isn't known
// in the map.
func (m dnsMap) resolveMemory(ctx context.Context, network, addr string) (_ netip.AddrPort, err error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		// addr malformed or invalid port.
		return netip.AddrPort{}, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		// addr was literal ip:port.
		return netip.AddrPortFrom(ip, port), nil
	}

	// Host is not an IP, so assume it's a DNS name.

	// Try MagicDNS first, otherwise a real DNS lookup.
	ip := m[canonMapKey(host)]
	if ip.IsValid() {
		return netip.AddrPortFrom(ip, port), nil
	}

	return netip.AddrPort{}, errUnresolved
}

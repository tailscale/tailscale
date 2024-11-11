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

	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
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

func dnsMapFromNetworkMap(nm *netmap.NetworkMap) dnsMap {
	if nm == nil {
		return nil
	}
	ret := make(dnsMap)
	suffix := nm.MagicDNSSuffix()
	have4 := false
	addrs := nm.GetAddresses()
	if nm.Name != "" && addrs.Len() > 0 {
		ip := addrs.At(0).Addr()
		ret[canonMapKey(nm.Name)] = ip
		if dnsname.HasSuffix(nm.Name, suffix) {
			ret[canonMapKey(dnsname.TrimSuffix(nm.Name, suffix))] = ip
		}
		for _, p := range addrs.All() {
			if p.Addr().Is4() {
				have4 = true
			}
		}
	}
	for _, p := range nm.Peers {
		if p.Name() == "" {
			continue
		}
		for _, pfx := range p.Addresses().All() {
			ip := pfx.Addr()
			if ip.Is4() && !have4 {
				continue
			}
			ret[canonMapKey(p.Name())] = ip
			if dnsname.HasSuffix(p.Name(), suffix) {
				ret[canonMapKey(dnsname.TrimSuffix(p.Name(), suffix))] = ip
			}
			break
		}
	}
	for _, rec := range nm.DNS.ExtraRecords {
		if rec.Type != "" {
			continue
		}
		ip, err := netip.ParseAddr(rec.Value)
		if err != nil {
			continue
		}
		ret[canonMapKey(rec.Name)] = ip
	}
	return ret
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

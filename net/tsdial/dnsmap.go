// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
)

// dnsMap maps MagicDNS names (both base + FQDN) to their first IP.
// It must not be mutated once created.
//
// Example keys are "foo.domain.tld.beta.tailscale.net" and "foo",
// both without trailing dots.
type dnsMap map[string]netaddr.IP

func dnsMapFromNetworkMap(nm *netmap.NetworkMap) dnsMap {
	if nm == nil {
		return nil
	}
	ret := make(dnsMap)
	suffix := nm.MagicDNSSuffix()
	have4 := false
	if nm.Name != "" && len(nm.Addresses) > 0 {
		ip := nm.Addresses[0].IP()
		ret[strings.TrimRight(nm.Name, ".")] = ip
		if dnsname.HasSuffix(nm.Name, suffix) {
			ret[dnsname.TrimSuffix(nm.Name, suffix)] = ip
		}
		for _, a := range nm.Addresses {
			if a.IP().Is4() {
				have4 = true
			}
		}
	}
	for _, p := range nm.Peers {
		if p.Name == "" {
			continue
		}
		for _, a := range p.Addresses {
			ip := a.IP()
			if ip.Is4() && !have4 {
				continue
			}
			ret[strings.TrimRight(p.Name, ".")] = ip
			if dnsname.HasSuffix(p.Name, suffix) {
				ret[dnsname.TrimSuffix(p.Name, suffix)] = ip
			}
			break
		}
	}
	for _, rec := range nm.DNS.ExtraRecords {
		if rec.Type != "" {
			continue
		}
		ip, err := netaddr.ParseIP(rec.Value)
		if err != nil {
			continue
		}
		ret[strings.TrimRight(rec.Name, ".")] = ip
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
func (m dnsMap) resolveMemory(ctx context.Context, network, addr string) (_ netaddr.IPPort, err error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		// addr malformed or invalid port.
		return netaddr.IPPort{}, err
	}
	if ip, err := netaddr.ParseIP(host); err == nil {
		// addr was literal ip:port.
		return netaddr.IPPortFrom(ip, port), nil
	}

	// Host is not an IP, so assume it's a DNS name.

	// Try MagicDNS first, otherwise a real DNS lookup.
	ip := m[host]
	if !ip.IsZero() {
		return netaddr.IPPortFrom(ip, port), nil
	}

	return netaddr.IPPort{}, errUnresolved
}

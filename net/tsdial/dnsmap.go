// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdial

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
)

// DNSMap maps MagicDNS names (both base + FQDN) to their first IP.
// It must not be mutated once created.
//
// Example keys are "foo.domain.tld.beta.tailscale.net" and "foo",
// both without trailing dots.
type DNSMap map[string]netaddr.IP

func DNSMapFromNetworkMap(nm *netmap.NetworkMap) DNSMap {
	ret := make(DNSMap)
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

// Resolve resolves addr into an IP:port using first the MagicDNS contents
// of m, else using the system resolver.
func (m DNSMap) Resolve(ctx context.Context, addr string) (netaddr.IPPort, error) {
	ipp, pippErr := netaddr.ParseIPPort(addr)
	if pippErr == nil {
		return ipp, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// addr is malformed.
		return netaddr.IPPort{}, err
	}
	if _, err := netaddr.ParseIP(host); err == nil {
		// The host part of addr was an IP, so the netaddr.ParseIPPort above should've
		// passed. Must've been a bad port number. Return the original error.
		return netaddr.IPPort{}, pippErr
	}
	port16, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netaddr.IPPort{}, fmt.Errorf("invalid port in address %q", addr)
	}

	// Host is not an IP, so assume it's a DNS name.

	// Try MagicDNS first, otherwise a real DNS lookup.
	ip := m[host]
	if !ip.IsZero() {
		return netaddr.IPPortFrom(ip, uint16(port16)), nil
	}

	// TODO(bradfitz): wire up net/dnscache too.

	// No MagicDNS name so try real DNS.
	var r net.Resolver
	ips, err := r.LookupIP(ctx, "ip", host)
	if err != nil {
		return netaddr.IPPort{}, err
	}
	if len(ips) == 0 {
		return netaddr.IPPort{}, fmt.Errorf("DNS lookup returned no results for %q", host)
	}
	ip, _ = netaddr.FromStdIP(ips[0])
	return netaddr.IPPortFrom(ip, uint16(port16)), nil
}

// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

import (
	"fmt"

	"inet.af/netaddr"
	"tailscale.com/tailcfg"
)

// MatchesFromFilterRules converts tailcfg FilterRules into Matches.
// If an error is returned, the Matches result is still valid,
// containing the rules that were successfully converted.
func MatchesFromFilterRules(pf []tailcfg.FilterRule) (Matches, error) {
	mm := make([]Match, 0, len(pf))
	var erracc error

	for _, r := range pf {
		m := Match{}

		for i, s := range r.SrcIPs {
			bits := 32
			if len(r.SrcBits) > i {
				bits = r.SrcBits[i]
			}
			net, err := parseIP(s, bits)
			if err != nil && erracc == nil {
				erracc = err
				continue
			}
			m.Srcs = append(m.Srcs, net)
		}

		for _, d := range r.DstPorts {
			bits := 32
			if d.Bits != nil {
				bits = *d.Bits
			}
			net, err := parseIP(d.IP, bits)
			if err != nil && erracc == nil {
				erracc = err
				continue
			}
			m.Dsts = append(m.Dsts, NetPortRange{
				Net: net,
				Ports: PortRange{
					First: d.Ports.First,
					Last:  d.Ports.Last,
				},
			})
		}

		mm = append(mm, m)
	}
	return mm, erracc
}

func parseIP(host string, defaultBits int) (netaddr.IPPrefix, error) {
	if host == "*" {
		// User explicitly requested wildcard dst ip.
		// TODO: ipv6
		return netaddr.IPPrefix{IP: netaddr.IPv4(0, 0, 0, 0), Bits: 0}, nil
	}

	ip, err := netaddr.ParseIP(host)
	if err != nil {
		return netaddr.IPPrefix{}, fmt.Errorf("ports=%#v: invalid IP address", host)
	}
	if ip == netaddr.IPv4(0, 0, 0, 0) {
		// For clarity, reject 0.0.0.0 as an input
		return netaddr.IPPrefix{}, fmt.Errorf("ports=%#v: to allow all IP addresses, use *:port, not 0.0.0.0:port", host)
	}
	if !ip.Is4() {
		// TODO: ipv6
		return netaddr.IPPrefix{}, fmt.Errorf("ports=%#v: invalid IPv4 address", host)
	}
	if defaultBits < 0 || defaultBits > 32 {
		return netaddr.IPPrefix{}, fmt.Errorf("invalid CIDR size %d for host %q", defaultBits, host)
	}
	return netaddr.IPPrefix{
		IP:   ip,
		Bits: uint8(defaultBits),
	}, nil
}

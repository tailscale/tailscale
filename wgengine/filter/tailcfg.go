// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

import (
	"fmt"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
)

var defaultProtos = []packet.IPProto{
	packet.TCP,
	packet.UDP,
	packet.ICMPv4,
	packet.ICMPv6,
}

// MatchesFromFilterRules converts tailcfg FilterRules into Matches.
// If an error is returned, the Matches result is still valid,
// containing the rules that were successfully converted.
func MatchesFromFilterRules(pf []tailcfg.FilterRule) ([]Match, error) {
	mm := make([]Match, 0, len(pf))
	var erracc error

	for _, r := range pf {
		m := Match{}

		if len(r.IPProto) == 0 {
			m.IPProto = append([]packet.IPProto(nil), defaultProtos...)
		} else {
			m.IPProto = make([]packet.IPProto, 0, len(r.IPProto))
			for _, n := range r.IPProto {
				if n >= 0 && n <= 0xff {
					m.IPProto = append(m.IPProto, packet.IPProto(n))
				}
			}
		}

		for i, s := range r.SrcIPs {
			var bits *int
			if len(r.SrcBits) > i {
				bits = &r.SrcBits[i]
			}
			nets, err := parseIPSet(s, bits)
			if err != nil && erracc == nil {
				erracc = err
				continue
			}
			m.Srcs = append(m.Srcs, nets...)
		}

		for _, d := range r.DstPorts {
			nets, err := parseIPSet(d.IP, d.Bits)
			if err != nil && erracc == nil {
				erracc = err
				continue
			}
			for _, net := range nets {
				m.Dsts = append(m.Dsts, NetPortRange{
					Net: net,
					Ports: PortRange{
						First: d.Ports.First,
						Last:  d.Ports.Last,
					},
				})
			}
		}

		mm = append(mm, m)
	}
	return mm, erracc
}

var (
	zeroIP4 = netaddr.IPv4(0, 0, 0, 0)
	zeroIP6 = netaddr.IPFrom16([16]byte{})
)

// parseIPSet parses arg as one:
//
//     * an IP address (IPv4 or IPv6)
//     * the string "*" to match everything (both IPv4 & IPv6)
//     * a CIDR (e.g. "192.168.0.0/16")
//     * a range of two IPs, inclusive, separated by hyphen ("2eff::1-2eff::0800")
//
// bits, if non-nil, is the legacy SrcBits CIDR length to make a IP
// address (without a slash) treated as a CIDR of *bits length.
//
// TODO(bradfitz): make this return an IPSet and plumb that all
// around, and ultimately use a new version of IPSet.ContainsFunc like
// Contains16Func that works in [16]byte address, so we we can match
// at runtime without allocating?
func parseIPSet(arg string, bits *int) ([]netaddr.IPPrefix, error) {
	if arg == "*" {
		// User explicitly requested wildcard.
		return []netaddr.IPPrefix{
			{IP: zeroIP4, Bits: 0},
			{IP: zeroIP6, Bits: 0},
		}, nil
	}
	if strings.Contains(arg, "/") {
		pfx, err := netaddr.ParseIPPrefix(arg)
		if err != nil {
			return nil, err
		}
		if pfx != pfx.Masked() {
			return nil, fmt.Errorf("%v contains non-network bits set", pfx)
		}
		return []netaddr.IPPrefix{pfx}, nil
	}
	if strings.Count(arg, "-") == 1 {
		i := strings.Index(arg, "-")
		ip1s, ip2s := arg[:i], arg[i+1:]
		ip1, err := netaddr.ParseIP(ip1s)
		if err != nil {
			return nil, err
		}
		ip2, err := netaddr.ParseIP(ip2s)
		if err != nil {
			return nil, err
		}
		r := netaddr.IPRange{From: ip1, To: ip2}
		if !r.Valid() {
			return nil, fmt.Errorf("invalid IP range %q", arg)
		}
		return r.Prefixes(), nil
	}
	ip, err := netaddr.ParseIP(arg)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address %q", arg)
	}
	bits8 := ip.BitLen()
	if bits != nil {
		if *bits < 0 || *bits > int(bits8) {
			return nil, fmt.Errorf("invalid CIDR size %d for IP %q", *bits, arg)
		}
		bits8 = uint8(*bits)
	}
	return []netaddr.IPPrefix{{IP: ip, Bits: bits8}}, nil
}

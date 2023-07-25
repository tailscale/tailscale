// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package filter

import (
	"fmt"
	"net/netip"
	"strings"

	"go4.org/netipx"
	"tailscale.com/net/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
)

var defaultProtos = []ipproto.Proto{
	ipproto.TCP,
	ipproto.UDP,
	ipproto.ICMPv4,
	ipproto.ICMPv6,
}

// MatchesFromFilterRules converts tailcfg FilterRules into Matches.
// If an error is returned, the Matches result is still valid,
// containing the rules that were successfully converted.
func MatchesFromFilterRules(pf []tailcfg.FilterRule) ([]Match, error) {
	mm := make([]Match, 0, len(pf))
	var erracc error

	for _, r := range pf {
		// Profiling determined that this function was spending a lot
		// of time in runtime.growslice. As such, we attempt to
		// pre-allocate some slices. Multipliers were chosen arbitrarily.
		m := Match{
			Srcs: make([]netip.Prefix, 0, len(r.SrcIPs)),
			Dsts: make([]NetPortRange, 0, 2*len(r.DstPorts)),
			Caps: make([]CapMatch, 0, 3*len(r.CapGrant)),
		}

		if len(r.IPProto) == 0 {
			m.IPProto = append([]ipproto.Proto(nil), defaultProtos...)
		} else {
			m.IPProto = make([]ipproto.Proto, 0, len(r.IPProto))
			for _, n := range r.IPProto {
				if n >= 0 && n <= 0xff {
					m.IPProto = append(m.IPProto, ipproto.Proto(n))
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
		for _, cm := range r.CapGrant {
			for _, dstNet := range cm.Dsts {
				for _, cap := range cm.Caps {
					m.Caps = append(m.Caps, CapMatch{
						Dst: dstNet,
						Cap: cap,
					})
				}
				for cap, val := range cm.CapMap {
					m.Caps = append(m.Caps, CapMatch{
						Dst:    dstNet,
						Cap:    tailcfg.PeerCapability(cap),
						Values: val,
					})
				}
			}
		}

		mm = append(mm, m)
	}
	return mm, erracc
}

var (
	zeroIP4 = netaddr.IPv4(0, 0, 0, 0)
	zeroIP6 = netip.AddrFrom16([16]byte{})
)

// parseIPSet parses arg as one:
//
//   - an IP address (IPv4 or IPv6)
//   - the string "*" to match everything (both IPv4 & IPv6)
//   - a CIDR (e.g. "192.168.0.0/16")
//   - a range of two IPs, inclusive, separated by hyphen ("2eff::1-2eff::0800")
//
// bits, if non-nil, is the legacy SrcBits CIDR length to make a IP
// address (without a slash) treated as a CIDR of *bits length.
//
// TODO(bradfitz): make this return an IPSet and plumb that all
// around, and ultimately use a new version of IPSet.ContainsFunc like
// Contains16Func that works in [16]byte address, so we we can match
// at runtime without allocating?
func parseIPSet(arg string, bits *int) ([]netip.Prefix, error) {
	if arg == "*" {
		// User explicitly requested wildcard.
		return []netip.Prefix{
			netip.PrefixFrom(zeroIP4, 0),
			netip.PrefixFrom(zeroIP6, 0),
		}, nil
	}
	if strings.Contains(arg, "/") {
		pfx, err := netip.ParsePrefix(arg)
		if err != nil {
			return nil, err
		}
		if pfx != pfx.Masked() {
			return nil, fmt.Errorf("%v contains non-network bits set", pfx)
		}
		return []netip.Prefix{pfx}, nil
	}
	if strings.Count(arg, "-") == 1 {
		ip1s, ip2s, _ := strings.Cut(arg, "-")
		ip1, err := netip.ParseAddr(ip1s)
		if err != nil {
			return nil, err
		}
		ip2, err := netip.ParseAddr(ip2s)
		if err != nil {
			return nil, err
		}
		r := netipx.IPRangeFrom(ip1, ip2)
		if !r.Valid() {
			return nil, fmt.Errorf("invalid IP range %q", arg)
		}
		return r.Prefixes(), nil
	}
	ip, err := netip.ParseAddr(arg)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address %q", arg)
	}
	bits8 := uint8(ip.BitLen())
	if bits != nil {
		if *bits < 0 || *bits > int(bits8) {
			return nil, fmt.Errorf("invalid CIDR size %d for IP %q", *bits, arg)
		}
		bits8 = uint8(*bits)
	}
	return []netip.Prefix{netip.PrefixFrom(ip, int(bits8))}, nil
}

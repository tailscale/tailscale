// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package filter

import (
	"fmt"
	"net/netip"
	"strings"

	"go4.org/netipx"
	"tailscale.com/net/ipset"
	"tailscale.com/net/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
)

var defaultProtos = []ipproto.Proto{
	ipproto.TCP,
	ipproto.UDP,
	ipproto.ICMPv4,
	ipproto.ICMPv6,
}

var defaultProtosView = views.SliceOf(defaultProtos)

// MatchesFromFilterRules converts tailcfg FilterRules into Matches.
// If an error is returned, the Matches result is still valid,
// containing the rules that were successfully converted.
func MatchesFromFilterRules(pf []tailcfg.FilterRule) ([]Match, error) {
	mm := make([]Match, 0, len(pf))
	var erracc error

	for _, r := range pf {
		if len(r.SrcBits) > 0 {
			return nil, fmt.Errorf("unexpected SrcBits; control plane should not send this to this client version")
		}
		// Profiling determined that this function was spending a lot
		// of time in runtime.growslice. As such, we attempt to
		// pre-allocate some slices. Multipliers were chosen arbitrarily.
		m := Match{
			Srcs: make([]netip.Prefix, 0, len(r.SrcIPs)),
			Dsts: make([]NetPortRange, 0, 2*len(r.DstPorts)),
			Caps: make([]CapMatch, 0, 3*len(r.CapGrant)),
		}

		if len(r.IPProto) == 0 {
			m.IPProto = defaultProtosView
		} else {
			filtered := make([]ipproto.Proto, 0, len(r.IPProto))
			for _, n := range r.IPProto {
				if n >= 0 && n <= 0xff {
					filtered = append(filtered, ipproto.Proto(n))
				}
			}
			m.IPProto = views.SliceOf(filtered)
		}

		for _, s := range r.SrcIPs {
			nets, cap, err := parseIPSet(s)
			if err != nil && erracc == nil {
				erracc = err
				continue
			}
			m.Srcs = append(m.Srcs, nets...)
			if cap != "" {
				m.SrcCaps = append(m.SrcCaps, cap)
			}
		}
		m.SrcsContains = ipset.NewContainsIPFunc(views.SliceOf(m.Srcs))

		for _, d := range r.DstPorts {
			if d.Bits != nil {
				return nil, fmt.Errorf("unexpected DstBits; control plane should not send this to this client version")
			}
			nets, cap, err := parseIPSet(d.IP)
			if err != nil && erracc == nil {
				erracc = err
				continue
			}
			if cap != "" {
				erracc = fmt.Errorf("unexpected capability %q in DstPorts", cap)
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
//   - "cap:<peer-node-capability>" to match a peer node capability
//
// TODO(bradfitz): make this return an IPSet and plumb that all
// around, and ultimately use a new version of IPSet.ContainsFunc like
// Contains16Func that works in [16]byte address, so we we can match
// at runtime without allocating?
func parseIPSet(arg string) (prefixes []netip.Prefix, peerCap tailcfg.NodeCapability, err error) {
	if arg == "*" {
		// User explicitly requested wildcard.
		return []netip.Prefix{
			netip.PrefixFrom(zeroIP4, 0),
			netip.PrefixFrom(zeroIP6, 0),
		}, "", nil
	}
	if cap, ok := strings.CutPrefix(arg, "cap:"); ok {
		return nil, tailcfg.NodeCapability(cap), nil
	}
	if strings.Contains(arg, "/") {
		pfx, err := netip.ParsePrefix(arg)
		if err != nil {
			return nil, "", err
		}
		if pfx != pfx.Masked() {
			return nil, "", fmt.Errorf("%v contains non-network bits set", pfx)
		}
		return []netip.Prefix{pfx}, "", nil
	}
	if strings.Count(arg, "-") == 1 {
		ip1s, ip2s, _ := strings.Cut(arg, "-")
		ip1, err := netip.ParseAddr(ip1s)
		if err != nil {
			return nil, "", err
		}
		ip2, err := netip.ParseAddr(ip2s)
		if err != nil {
			return nil, "", err
		}
		r := netipx.IPRangeFrom(ip1, ip2)
		if !r.IsValid() {
			return nil, "", fmt.Errorf("invalid IP range %q", arg)
		}
		return r.Prefixes(), "", nil
	}
	ip, err := netip.ParseAddr(arg)
	if err != nil {
		return nil, "", fmt.Errorf("invalid IP address %q", arg)
	}
	return []netip.Prefix{netip.PrefixFrom(ip, ip.BitLen())}, "", nil
}

// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

import (
	"fmt"
	"math/bits"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/net/packet"
)

type net4 struct {
	ip   packet.IP4
	mask packet.IP4
}

func net4FromIPPrefix(pfx netaddr.IPPrefix) net4 {
	if !pfx.IP.Is4() {
		panic("net4FromIPPrefix given non-ipv4 prefix")
	}
	return net4{
		ip:   packet.IP4FromNetaddr(pfx.IP),
		mask: netmask4(pfx.Bits),
	}
}

func nets4FromIPPrefixes(pfxs []netaddr.IPPrefix) (ret []net4) {
	for _, pfx := range pfxs {
		if pfx.IP.Is4() {
			ret = append(ret, net4FromIPPrefix(pfx))
		}
	}
	return ret
}

func (n net4) Contains(ip packet.IP4) bool {
	return (n.ip & n.mask) == (ip & n.mask)
}

func (n net4) Bits() int {
	return 32 - bits.TrailingZeros32(uint32(n.mask))
}

func (n net4) String() string {
	b := n.Bits()
	if b == 32 {
		return n.ip.String()
	} else if b == 0 {
		return "*"
	} else {
		return fmt.Sprintf("%s/%d", n.ip, b)
	}
}

type npr4 struct {
	net   net4
	ports PortRange
}

func (npr npr4) String() string {
	return fmt.Sprintf("%s:%s", npr.net, npr.ports)
}

type match4 struct {
	dsts []npr4
	srcs []net4
}

type matches4 []match4

func (ms matches4) String() string {
	var b strings.Builder
	for _, m := range ms {
		fmt.Fprintf(&b, "%s => %s\n", m.srcs, m.dsts)
	}
	return b.String()
}

func newMatches4(ms []Match) (ret matches4) {
	for _, m := range ms {
		var m4 match4
		for _, src := range m.Srcs {
			if src.IP.Is4() {
				m4.srcs = append(m4.srcs, net4FromIPPrefix(src))
			}
		}
		for _, dst := range m.Dsts {
			if dst.Net.IP.Is4() {
				m4.dsts = append(m4.dsts, npr4{net4FromIPPrefix(dst.Net), dst.Ports})
			}
		}
		if len(m4.srcs) > 0 && len(m4.dsts) > 0 {
			ret = append(ret, m4)
		}
	}
	return ret
}

// match returns whether q's source IP and destination IP:port match
// any of ms.
func (ms matches4) match(q *packet.Parsed) bool {
	for _, m := range ms {
		if !ip4InList(q.SrcIP4, m.srcs) {
			continue
		}
		for _, dst := range m.dsts {
			if !dst.net.Contains(q.DstIP4) {
				continue
			}
			if !dst.ports.contains(q.DstPort) {
				continue
			}
			return true
		}
	}
	return false
}

// matchIPsOnly returns whether q's source and destination IP match
// any of ms.
func (ms matches4) matchIPsOnly(q *packet.Parsed) bool {
	for _, m := range ms {
		if !ip4InList(q.SrcIP4, m.srcs) {
			continue
		}
		for _, dst := range m.dsts {
			if dst.net.Contains(q.DstIP4) {
				return true
			}
		}
	}
	return false
}

func netmask4(bits uint8) packet.IP4 {
	b := ^uint32((1 << (32 - bits)) - 1)
	return packet.IP4(b)
}

func ip4InList(ip packet.IP4, netlist []net4) bool {
	for _, net := range netlist {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

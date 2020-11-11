// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

import (
	"fmt"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/net/packet"
)

type net6 struct {
	ip   packet.IP6
	bits uint8
}

func net6FromIPPrefix(pfx netaddr.IPPrefix) net6 {
	if !pfx.IP.Is6() {
		panic("net6FromIPPrefix given non-ipv6 prefix")
	}
	return net6{
		ip:   packet.IP6FromNetaddr(pfx.IP),
		bits: pfx.Bits,
	}
}

func nets6FromIPPrefixes(pfxs []netaddr.IPPrefix) (ret []net6) {
	for _, pfx := range pfxs {
		if pfx.IP.Is6() {
			ret = append(ret, net6FromIPPrefix(pfx))
		}
	}
	return ret
}

func (n net6) Contains(ip packet.IP6) bool {
	// Implementation stolen from inet.af/netaddr
	bits := n.bits
	for i := 0; bits > 0 && i < len(n.ip); i++ {
		m := uint8(255)
		if bits < 8 {
			zeros := 8 - bits
			m = m >> zeros << zeros
		}
		if n.ip[i]&m != ip[i]&m {
			return false
		}
		if bits < 8 {
			break
		}
		bits -= 8
	}
	return true
}

func (n net6) String() string {
	switch n.bits {
	case 128:
		return n.ip.String()
	case 0:
		return "*"
	default:
		return fmt.Sprintf("%s/%d", n.ip, n.bits)
	}
}

type npr6 struct {
	net   net6
	ports PortRange
}

func (npr npr6) String() string {
	return fmt.Sprintf("%s:%s", npr.net, npr.ports)
}

type match6 struct {
	srcs []net6
	dsts []npr6
}

type matches6 []match6

func (ms matches6) String() string {
	var b strings.Builder
	for _, m := range ms {
		fmt.Fprintf(&b, "%s => %s\n", m.srcs, m.dsts)
	}
	return b.String()
}

func newMatches6(ms []Match) (ret matches6) {
	for _, m := range ms {
		var m6 match6
		for _, src := range m.Srcs {
			if src.IP.Is6() {
				m6.srcs = append(m6.srcs, net6FromIPPrefix(src))
			}
		}
		for _, dst := range m.Dsts {
			if dst.Net.IP.Is6() {
				m6.dsts = append(m6.dsts, npr6{net6FromIPPrefix(dst.Net), dst.Ports})
			}
		}
		if len(m6.srcs) > 0 && len(m6.dsts) > 0 {
			ret = append(ret, m6)
		}
	}
	return ret
}

func (ms matches6) match(q *packet.Parsed) bool {
	for _, m := range ms {
		if !ip6InList(q.SrcIP6, m.srcs) {
			continue
		}
		for _, dst := range m.dsts {
			if !dst.net.Contains(q.DstIP6) {
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

func (ms matches6) matchIPsOnly(q *packet.Parsed) bool {
	for _, m := range ms {
		if !ip6InList(q.SrcIP6, m.srcs) {
			continue
		}
		for _, dst := range m.dsts {
			if dst.net.Contains(q.DstIP6) {
				return true
			}
		}
	}
	return false
}

func ip6InList(ip packet.IP6, netlist []net6) bool {
	for _, net := range netlist {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

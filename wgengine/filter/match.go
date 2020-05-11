// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

import (
	"fmt"
	"math/bits"
	"net"
	"strings"

	"tailscale.com/wgengine/packet"
)

func NewIP(ip net.IP) packet.IP {
	return packet.NewIP(ip)
}

type Net struct {
	IP   packet.IP
	Mask packet.IP
}

func (n Net) Includes(ip packet.IP) bool {
	return (n.IP & n.Mask) == (ip & n.Mask)
}

func (n Net) Bits() int {
	return 32 - bits.TrailingZeros32(uint32(n.Mask))
}

func (n Net) String() string {
	b := n.Bits()
	if b == 32 {
		return n.IP.String()
	} else if b == 0 {
		return "*"
	} else {
		return fmt.Sprintf("%s/%d", n.IP, b)
	}
}

var NetAny = Net{0, 0}
var NetNone = Net{^packet.IP(0), ^packet.IP(0)}

func Netmask(bits int) packet.IP {
	b := ^uint32((1 << (32 - bits)) - 1)
	return packet.IP(b)
}

type PortRange struct {
	First, Last uint16
}

var PortRangeAny = PortRange{0, 65535}

func (pr PortRange) String() string {
	if pr.First == 0 && pr.Last == 65535 {
		return "*"
	} else if pr.First == pr.Last {
		return fmt.Sprintf("%d", pr.First)
	} else {
		return fmt.Sprintf("%d-%d", pr.First, pr.Last)
	}
}

type NetPortRange struct {
	Net   Net
	Ports PortRange
}

var NetPortRangeAny = NetPortRange{NetAny, PortRangeAny}

func (ipr NetPortRange) String() string {
	return fmt.Sprintf("%v:%v", ipr.Net, ipr.Ports)
}

type Match struct {
	Dsts []NetPortRange
	Srcs []Net
}

func (m Match) Clone() (res Match) {
	if m.Dsts != nil {
		res.Dsts = append([]NetPortRange{}, m.Dsts...)
	}
	if m.Srcs != nil {
		res.Srcs = append([]Net{}, m.Srcs...)
	}
	return res
}

func (m Match) String() string {
	srcs := []string{}
	for _, src := range m.Srcs {
		srcs = append(srcs, src.String())
	}
	dsts := []string{}
	for _, dst := range m.Dsts {
		dsts = append(dsts, dst.String())
	}

	var ss, ds string
	if len(srcs) == 1 {
		ss = srcs[0]
	} else {
		ss = "[" + strings.Join(srcs, ",") + "]"
	}
	if len(dsts) == 1 {
		ds = dsts[0]
	} else {
		ds = "[" + strings.Join(dsts, ",") + "]"
	}
	return fmt.Sprintf("%v=>%v", ss, ds)
}

type Matches []Match

func (m Matches) Clone() (res Matches) {
	for _, match := range m {
		res = append(res, match.Clone())
	}
	return res
}

func ipInList(ip packet.IP, netlist []Net) bool {
	for _, net := range netlist {
		if net.Includes(ip) {
			return true
		}
	}
	return false
}

func matchIPPorts(mm Matches, q *packet.QDecode) bool {
	for _, acl := range mm {
		for _, dst := range acl.Dsts {
			if !dst.Net.Includes(q.DstIP) {
				continue
			}
			if q.DstPort < dst.Ports.First || q.DstPort > dst.Ports.Last {
				continue
			}
			if !ipInList(q.SrcIP, acl.Srcs) {
				// Skip other dests in this acl, since
				// the src will never match.
				break
			}
			return true
		}
	}
	return false
}

func matchIPWithoutPorts(mm Matches, q *packet.QDecode) bool {
	for _, acl := range mm {
		for _, dst := range acl.Dsts {
			if !dst.Net.Includes(q.DstIP) {
				continue
			}
			if !ipInList(q.SrcIP, acl.Srcs) {
				// Skip other dests in this acl, since
				// the src will never match.
				break
			}
			return true
		}
	}
	return false
}

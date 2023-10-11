// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package filter

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
)

//go:generate go run tailscale.com/cmd/cloner --type=Match,CapMatch

// PortRange is a range of TCP and UDP ports.
type PortRange struct {
	First, Last uint16 // inclusive
}

var allPorts = PortRange{0, 0xffff}

func (pr PortRange) String() string {
	if pr.First == 0 && pr.Last == 65535 {
		return "*"
	} else if pr.First == pr.Last {
		return fmt.Sprintf("%d", pr.First)
	} else {
		return fmt.Sprintf("%d-%d", pr.First, pr.Last)
	}
}

// contains returns whether port is in pr.
func (pr PortRange) contains(port uint16) bool {
	return port >= pr.First && port <= pr.Last
}

// NetPortRange combines an IP address prefix and PortRange.
type NetPortRange struct {
	Net   netip.Prefix
	Ports PortRange
}

func (npr NetPortRange) String() string {
	return fmt.Sprintf("%v:%v", npr.Net, npr.Ports)
}

// CapMatch is a capability grant match predicate.
type CapMatch struct {
	// Dst is the IP prefix that the destination IP address matches against
	// to get the capability.
	Dst netip.Prefix

	// Cap is the capability that's granted if the destination IP addresses
	// matches Dst.
	Cap tailcfg.PeerCapability

	// Values are the raw JSON values of the capability.
	// See tailcfg.PeerCapability and tailcfg.PeerCapMap for details.
	Values []tailcfg.RawMessage
}

// Match matches packets from any IP address in Srcs to any ip:port in
// Dsts.
type Match struct {
	IPProto []ipproto.Proto // required set (no default value at this layer)
	Srcs    []netip.Prefix
	Dsts    []NetPortRange // optional, if Srcs match
	Caps    []CapMatch     // optional, if Srcs match
}

func (m Match) String() string {
	// TODO(bradfitz): use strings.Builder, add String tests
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
	return fmt.Sprintf("%v%v=>%v", m.IPProto, ss, ds)
}

type matches []Match

func (ms matches) match(q *packet.Parsed) bool {
	for _, m := range ms {
		if !slices.Contains(m.IPProto, q.IPProto) {
			continue
		}
		if !ipInList(q.Src.Addr(), m.Srcs) {
			continue
		}
		for _, dst := range m.Dsts {
			if !dst.Net.Contains(q.Dst.Addr()) {
				continue
			}
			if !dst.Ports.contains(q.Dst.Port()) {
				continue
			}
			return true
		}
	}
	return false
}

func (ms matches) matchIPsOnly(q *packet.Parsed) bool {
	for _, m := range ms {
		if !ipInList(q.Src.Addr(), m.Srcs) {
			continue
		}
		for _, dst := range m.Dsts {
			if dst.Net.Contains(q.Dst.Addr()) {
				return true
			}
		}
	}
	return false
}

// matchProtoAndIPsOnlyIfAllPorts reports q matches any Match in ms where the
// Match if for the right IP Protocol and IP address, but ports are
// ignored, as long as the match is for the entire uint16 port range.
func (ms matches) matchProtoAndIPsOnlyIfAllPorts(q *packet.Parsed) bool {
	for _, m := range ms {
		if !slices.Contains(m.IPProto, q.IPProto) {
			continue
		}
		if !ipInList(q.Src.Addr(), m.Srcs) {
			continue
		}
		for _, dst := range m.Dsts {
			if dst.Ports != allPorts {
				continue
			}
			if dst.Net.Contains(q.Dst.Addr()) {
				return true
			}
		}
	}
	return false
}

func ipInList(ip netip.Addr, netlist []netip.Prefix) bool {
	for _, net := range netlist {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

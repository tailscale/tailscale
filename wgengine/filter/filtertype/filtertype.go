// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package filtertype defines the types used by wgengine/filter.
package filtertype

import (
	"fmt"
	"net/netip"
	"strings"

	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
)

//go:generate go run tailscale.com/cmd/cloner --type=Match,CapMatch

// PortRange is a range of TCP and UDP ports.
type PortRange struct {
	First, Last uint16 // inclusive
}

var AllPorts = PortRange{0, 0xffff}

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
func (pr PortRange) Contains(port uint16) bool {
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
	// IPProto is the set of IP protocol numbers for which this match applies.
	// It is required. There is no default value at this layer.
	// If empty, it doesn't match.
	IPProto views.Slice[ipproto.Proto]

	// Srcs is the set of source IP prefixes for which this match applies. A
	// Match can match by either its source IP address being in Srcs (which
	// SrcsContains tests) or if the source IP is of a known peer self address
	// that contains a NodeCapability listed in SrcCaps.
	Srcs []netip.Prefix
	// SrcsContains is an optimized function that reports whether Addr is in
	// Srcs, using the best search method for the size and shape of Srcs.
	SrcsContains func(netip.Addr) bool `json:"-"` // report whether Addr is in Srcs

	// SrcCaps is an alternative way to match packets. If the peer's source IP
	// has one of these capabilities, it's also permitted. The peers are only
	// looked up by their self address (Node.Addresses) and not by subnet routes
	// they advertise.
	SrcCaps []tailcfg.NodeCapability

	Dsts []NetPortRange // optional, if source matches
	Caps []CapMatch     // optional, if source match
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

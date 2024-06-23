// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package filter

import (
	"net/netip"

	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter/filtertype"
)

type matches []filtertype.Match

func (ms matches) match(q *packet.Parsed, hasCap CapTestFunc) bool {
	for i := range ms {
		m := &ms[i]
		if !views.SliceContains(m.IPProto, q.IPProto) {
			continue
		}
		if !srcMatches(m, q.Src.Addr(), hasCap) {
			continue
		}
		for _, dst := range m.Dsts {
			if !dst.Net.Contains(q.Dst.Addr()) {
				continue
			}
			if !dst.Ports.Contains(q.Dst.Port()) {
				continue
			}
			return true
		}
	}
	return false
}

// srcMatches reports whether srcAddr matche the src requirements in m, either
// by Srcs (using SrcsContains), or by the node having a capability listed
// in SrcCaps using the provided hasCap function.
func srcMatches(m *filtertype.Match, srcAddr netip.Addr, hasCap CapTestFunc) bool {
	if m.SrcsContains(srcAddr) {
		return true
	}
	if hasCap != nil {
		for _, c := range m.SrcCaps {
			if hasCap(srcAddr, c) {
				return true
			}
		}
	}
	return false
}

// CapTestFunc is the function signature of a function that tests whether srcIP
// has a given capability.
//
// It it used in the fast path of evaluating filter rules so should be fast.
type CapTestFunc = func(srcIP netip.Addr, cap tailcfg.NodeCapability) bool

func (ms matches) matchIPsOnly(q *packet.Parsed, hasCap CapTestFunc) bool {
	srcAddr := q.Src.Addr()
	for _, m := range ms {
		if !m.SrcsContains(srcAddr) {
			continue
		}
		for _, dst := range m.Dsts {
			if dst.Net.Contains(q.Dst.Addr()) {
				return true
			}
		}
	}
	if hasCap != nil {
		for _, m := range ms {
			for _, c := range m.SrcCaps {
				if hasCap(srcAddr, c) {
					return true
				}
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
		if !views.SliceContains(m.IPProto, q.IPProto) {
			continue
		}
		if !m.SrcsContains(q.Src.Addr()) {
			continue
		}
		for _, dst := range m.Dsts {
			if dst.Ports != filtertype.AllPorts {
				continue
			}
			if dst.Net.Contains(q.Dst.Addr()) {
				return true
			}
		}
	}
	return false
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package filter

import (
	"slices"

	"tailscale.com/net/packet"
	"tailscale.com/wgengine/filter/filtertype"
)

type matches []filtertype.Match

func (ms matches) match(q *packet.Parsed) bool {
	for _, m := range ms {
		if !slices.Contains(m.IPProto, q.IPProto) {
			continue
		}
		if !m.SrcsContains(q.Src.Addr()) {
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

func (ms matches) matchIPsOnly(q *packet.Parsed) bool {
	for _, m := range ms {
		if !m.SrcsContains(q.Src.Addr()) {
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

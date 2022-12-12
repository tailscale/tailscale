// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package connstats maintains statistics about connections
// flowing through a TUN device (which operate at the IP layer).
package connstats

import (
	"net/netip"
	"sync"

	"tailscale.com/net/packet"
	"tailscale.com/types/netlogtype"
)

// Statistics maintains counters for every connection.
// All methods are safe for concurrent use.
// The zero value is ready for use.
type Statistics struct {
	mu       sync.Mutex
	virtual  map[netlogtype.Connection]netlogtype.Counts
	physical map[netlogtype.Connection]netlogtype.Counts
}

// UpdateTxVirtual updates the counters for a transmitted IP packet
// The source and destination of the packet directly correspond with
// the source and destination in netlogtype.Connection.
func (s *Statistics) UpdateTxVirtual(b []byte) {
	s.updateVirtual(b, false)
}

// UpdateRxVirtual updates the counters for a received IP packet.
// The source and destination of the packet are inverted with respect to
// the source and destination in netlogtype.Connection.
func (s *Statistics) UpdateRxVirtual(b []byte) {
	s.updateVirtual(b, true)
}

func (s *Statistics) updateVirtual(b []byte, receive bool) {
	var p packet.Parsed
	p.Decode(b)
	conn := netlogtype.Connection{Proto: p.IPProto, Src: p.Src, Dst: p.Dst}
	if receive {
		conn.Src, conn.Dst = conn.Dst, conn.Src
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.virtual == nil {
		s.virtual = make(map[netlogtype.Connection]netlogtype.Counts)
	}
	cnts := s.virtual[conn]
	if receive {
		cnts.RxPackets++
		cnts.RxBytes += uint64(len(b))
	} else {
		cnts.TxPackets++
		cnts.TxBytes += uint64(len(b))
	}
	s.virtual[conn] = cnts
}

// UpdateTxPhysical updates the counters for a transmitted wireguard packet
// The src is always a Tailscale IP address, representing some remote peer.
// The dst is a remote IP address and port that corresponds
// with some physical peer backing the Tailscale IP address.
func (s *Statistics) UpdateTxPhysical(src netip.Addr, dst netip.AddrPort, n int) {
	s.updatePhysical(src, dst, n, false)
}

// UpdateRxPhysical updates the counters for a received wireguard packet.
// The src is always a Tailscale IP address, representing some remote peer.
// The dst is a remote IP address and port that corresponds
// with some physical peer backing the Tailscale IP address.
func (s *Statistics) UpdateRxPhysical(src netip.Addr, dst netip.AddrPort, n int) {
	s.updatePhysical(src, dst, n, true)
}

func (s *Statistics) updatePhysical(src netip.Addr, dst netip.AddrPort, n int, receive bool) {
	conn := netlogtype.Connection{Src: netip.AddrPortFrom(src, 0), Dst: dst}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.physical == nil {
		s.physical = make(map[netlogtype.Connection]netlogtype.Counts)
	}
	cnts := s.physical[conn]
	if receive {
		cnts.RxPackets++
		cnts.RxBytes += uint64(n)
	} else {
		cnts.TxPackets++
		cnts.TxBytes += uint64(n)
	}
	s.physical[conn] = cnts
}

// Extract extracts and resets the counters for all active connections.
// It must be called periodically otherwise the memory used is unbounded.
func (s *Statistics) Extract() (virtual, physical map[netlogtype.Connection]netlogtype.Counts) {
	s.mu.Lock()
	defer s.mu.Unlock()
	virtual = s.virtual
	s.virtual = make(map[netlogtype.Connection]netlogtype.Counts)
	physical = s.physical
	s.physical = make(map[netlogtype.Connection]netlogtype.Counts)
	return virtual, physical
}

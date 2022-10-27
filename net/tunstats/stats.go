// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tunstats maintains statistics about connections
// flowing through a TUN device (which operate at the IP layer).
package tunstats

import (
	"sync"

	"tailscale.com/net/packet"
	"tailscale.com/types/netlogtype"
)

// Statistics maintains counters for every connection.
// All methods are safe for concurrent use.
// The zero value is ready for use.
type Statistics struct {
	mu sync.Mutex
	m  map[netlogtype.Connection]netlogtype.Counts
}

// UpdateTx updates the counters for a transmitted IP packet
// The source and destination of the packet directly correspond with
// the source and destination in netlogtype.Connection.
func (s *Statistics) UpdateTx(b []byte) {
	s.update(b, false)
}

// UpdateRx updates the counters for a received IP packet.
// The source and destination of the packet are inverted with respect to
// the source and destination in netlogtype.Connection.
func (s *Statistics) UpdateRx(b []byte) {
	s.update(b, true)
}

func (s *Statistics) update(b []byte, receive bool) {
	var p packet.Parsed
	p.Decode(b)
	conn := netlogtype.Connection{Proto: p.IPProto, Src: p.Src, Dst: p.Dst}
	if receive {
		conn.Src, conn.Dst = conn.Dst, conn.Src
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[netlogtype.Connection]netlogtype.Counts)
	}
	cnts := s.m[conn]
	if receive {
		cnts.RxPackets++
		cnts.RxBytes += uint64(len(b))
	} else {
		cnts.TxPackets++
		cnts.TxBytes += uint64(len(b))
	}
	s.m[conn] = cnts
}

// Extract extracts and resets the counters for all active connections.
// It must be called periodically otherwise the memory used is unbounded.
func (s *Statistics) Extract() map[netlogtype.Connection]netlogtype.Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.m
	s.m = make(map[netlogtype.Connection]netlogtype.Counts)
	return m
}

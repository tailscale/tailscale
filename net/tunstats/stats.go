// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tunstats maintains statistics about connections
// flowing through a TUN device (which operate at the IP layer).
package tunstats

import (
	"sync"

	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
)

// Statistics maintains counters for every connection.
// All methods are safe for concurrent use.
// The zero value is ready for use.
type Statistics struct {
	mu sync.Mutex
	m  map[flowtrack.Tuple]Counts
}

// Counts are statistics about a particular connection.
type Counts struct {
	TxPackets uint64 `json:"txPkts,omitempty"`
	TxBytes   uint64 `json:"txBytes,omitempty"`
	RxPackets uint64 `json:"rxPkts,omitempty"`
	RxBytes   uint64 `json:"rxBytes,omitempty"`
}

// Add adds the counts from both c1 and c2.
func (c1 Counts) Add(c2 Counts) Counts {
	c1.TxPackets += c2.TxPackets
	c1.TxBytes += c2.TxBytes
	c1.RxPackets += c2.RxPackets
	c1.RxBytes += c2.RxBytes
	return c1
}

// UpdateTx updates the counters for a transmitted IP packet
// The source and destination of the packet directly correspond with
// the source and destination in flowtrack.Tuple.
func (s *Statistics) UpdateTx(b []byte) {
	s.update(b, false)
}

// UpdateRx updates the counters for a received IP packet.
// The source and destination of the packet are inverted with respect to
// the source and destination in flowtrack.Tuple.
func (s *Statistics) UpdateRx(b []byte) {
	s.update(b, true)
}

func (s *Statistics) update(b []byte, receive bool) {
	var p packet.Parsed
	p.Decode(b)
	tuple := flowtrack.Tuple{Proto: p.IPProto, Src: p.Src, Dst: p.Dst}
	if receive {
		tuple.Src, tuple.Dst = tuple.Dst, tuple.Src
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[flowtrack.Tuple]Counts)
	}
	cnts := s.m[tuple]
	if receive {
		cnts.RxPackets++
		cnts.RxBytes += uint64(len(b))
	} else {
		cnts.TxPackets++
		cnts.TxBytes += uint64(len(b))
	}
	s.m[tuple] = cnts
}

// Extract extracts and resets the counters for all active connections.
// It must be called periodically otherwise the memory used is unbounded.
func (s *Statistics) Extract() map[flowtrack.Tuple]Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.m
	s.m = make(map[flowtrack.Tuple]Counts)
	return m
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_connstats

// Package connstats maintains statistics about connections
// flowing through a TUN device (which operate at the IP layer).
package connstats

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/netlogtype"
)

// Statistics maintains counters for every connection.
// All methods are safe for concurrent use.
// The zero value is ready for use.
type Statistics struct {
	maxConns int // immutable once set

	mu sync.Mutex
	connCnts

	connCntsCh  chan connCnts
	shutdownCtx context.Context
	shutdown    context.CancelFunc
	group       errgroup.Group
}

type connCnts struct {
	start    time.Time
	end      time.Time
	virtual  map[netlogtype.Connection]netlogtype.Counts
	physical map[netlogtype.Connection]netlogtype.Counts
}

// NewStatistics creates a data structure for tracking connection statistics
// that periodically dumps the virtual and physical connection counts
// depending on whether the maxPeriod or maxConns is exceeded.
// The dump function is called from a single goroutine.
// Shutdown must be called to cleanup resources.
func NewStatistics(maxPeriod time.Duration, maxConns int, dump func(start, end time.Time, virtual, physical map[netlogtype.Connection]netlogtype.Counts)) *Statistics {
	s := &Statistics{maxConns: maxConns}
	s.connCntsCh = make(chan connCnts, 256)
	s.shutdownCtx, s.shutdown = context.WithCancel(context.Background())
	s.group.Go(func() error {
		// TODO(joetsai): Using a ticker is problematic on mobile platforms
		// where waking up a process every maxPeriod when there is no activity
		// is a drain on battery life. Switch this instead to instead use
		// a time.Timer that is triggered upon network activity.
		ticker := new(time.Ticker)
		if maxPeriod > 0 {
			ticker = time.NewTicker(maxPeriod)
			defer ticker.Stop()
		}

		for {
			var cc connCnts
			select {
			case cc = <-s.connCntsCh:
			case <-ticker.C:
				cc = s.extract()
			case <-s.shutdownCtx.Done():
				cc = s.extract()
			}
			if len(cc.virtual)+len(cc.physical) > 0 && dump != nil {
				dump(cc.start, cc.end, cc.virtual, cc.physical)
			}
			if s.shutdownCtx.Err() != nil {
				return nil
			}
		}
	})
	return s
}

// UpdateTxVirtual updates the counters for a transmitted IP packet
// The source and destination of the packet directly correspond with
// the source and destination in netlogtype.Connection.
func (s *Statistics) UpdateTxVirtual(b []byte) {
	var p packet.Parsed
	p.Decode(b)
	s.UpdateVirtual(p.IPProto, p.Src, p.Dst, 1, len(b), false)
}

// UpdateRxVirtual updates the counters for a received IP packet.
// The source and destination of the packet are inverted with respect to
// the source and destination in netlogtype.Connection.
func (s *Statistics) UpdateRxVirtual(b []byte) {
	var p packet.Parsed
	p.Decode(b)
	s.UpdateVirtual(p.IPProto, p.Dst, p.Src, 1, len(b), true)
}

var (
	tailscaleServiceIPv4 = tsaddr.TailscaleServiceIP()
	tailscaleServiceIPv6 = tsaddr.TailscaleServiceIPv6()
)

func (s *Statistics) UpdateVirtual(proto ipproto.Proto, src, dst netip.AddrPort, packets, bytes int, receive bool) {
	// Network logging is defined as traffic between two Tailscale nodes.
	// Traffic with the internal Tailscale service is not with another node
	// and should not be logged. It also happens to be a high volume
	// amount of discrete traffic flows (e.g., DNS lookups).
	switch dst.Addr() {
	case tailscaleServiceIPv4, tailscaleServiceIPv6:
		return
	}

	conn := netlogtype.Connection{Proto: proto, Src: src, Dst: dst}

	s.mu.Lock()
	defer s.mu.Unlock()
	cnts, found := s.virtual[conn]
	if !found && !s.preInsertConn() {
		return
	}
	if receive {
		cnts.RxPackets += uint64(packets)
		cnts.RxBytes += uint64(bytes)
	} else {
		cnts.TxPackets += uint64(packets)
		cnts.TxBytes += uint64(bytes)
	}
	s.virtual[conn] = cnts
}

// UpdateTxPhysical updates the counters for zero or more transmitted wireguard packets.
// The src is always a Tailscale IP address, representing some remote peer.
// The dst is a remote IP address and port that corresponds
// with some physical peer backing the Tailscale IP address.
func (s *Statistics) UpdateTxPhysical(src netip.Addr, dst netip.AddrPort, packets, bytes int) {
	s.UpdatePhysical(0, netip.AddrPortFrom(src, 0), dst, packets, bytes, false)
}

// UpdateRxPhysical updates the counters for zero or more received wireguard packets.
// The src is always a Tailscale IP address, representing some remote peer.
// The dst is a remote IP address and port that corresponds
// with some physical peer backing the Tailscale IP address.
func (s *Statistics) UpdateRxPhysical(src netip.Addr, dst netip.AddrPort, packets, bytes int) {
	s.UpdatePhysical(0, netip.AddrPortFrom(src, 0), dst, packets, bytes, true)
}

func (s *Statistics) UpdatePhysical(proto ipproto.Proto, src, dst netip.AddrPort, packets, bytes int, receive bool) {
	conn := netlogtype.Connection{Proto: proto, Src: src, Dst: dst}

	s.mu.Lock()
	defer s.mu.Unlock()
	cnts, found := s.physical[conn]
	if !found && !s.preInsertConn() {
		return
	}
	if receive {
		cnts.RxPackets += uint64(packets)
		cnts.RxBytes += uint64(bytes)
	} else {
		cnts.TxPackets += uint64(packets)
		cnts.TxBytes += uint64(bytes)
	}
	s.physical[conn] = cnts
}

// preInsertConn updates the maps to handle insertion of a new connection.
// It reports false if insertion is not allowed (i.e., after shutdown).
func (s *Statistics) preInsertConn() bool {
	// Check whether insertion of a new connection will exceed maxConns.
	if len(s.virtual)+len(s.physical) == s.maxConns && s.maxConns > 0 {
		// Extract the current statistics and send it to the serializer.
		// Avoid blocking the network packet handling path.
		select {
		case s.connCntsCh <- s.extractLocked():
		default:
			// TODO(joetsai): Log that we are dropping an entire connCounts.
		}
	}

	// Initialize the maps if nil.
	if s.virtual == nil && s.physical == nil {
		s.start = time.Now().UTC()
		s.virtual = make(map[netlogtype.Connection]netlogtype.Counts)
		s.physical = make(map[netlogtype.Connection]netlogtype.Counts)
	}

	return s.shutdownCtx.Err() == nil
}

func (s *Statistics) extract() connCnts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.extractLocked()
}

func (s *Statistics) extractLocked() connCnts {
	if len(s.virtual)+len(s.physical) == 0 {
		return connCnts{}
	}
	s.end = time.Now().UTC()
	cc := s.connCnts
	s.connCnts = connCnts{}
	return cc
}

// TestExtract synchronously extracts the current network statistics map
// and resets the counters. This should only be used for testing purposes.
func (s *Statistics) TestExtract() (virtual, physical map[netlogtype.Connection]netlogtype.Counts) {
	cc := s.extract()
	return cc.virtual, cc.physical
}

// Shutdown performs a final flush of statistics.
// Statistics for any subsequent calls to Update will be dropped.
// It is safe to call Shutdown concurrently and repeatedly.
func (s *Statistics) Shutdown(context.Context) error {
	s.shutdown()
	return s.group.Wait()
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

type Snapshot struct {
	WhenNsec int64 // current time
	timeAcc  int64 // accumulated time (+NSecPerTx per transmit)

	LastSeqTx    int64 // last sequence number sent
	LastSeqRx    int64 // last sequence number received
	TotalLost    int64 // packets out-of-order or lost so far
	TotalOOO     int64 // packets out-of-order so far
	TotalBytesRx int64 // total bytes received so far
}

type Delta struct {
	DurationNsec int64
	TxPackets    int64
	RxPackets    int64
	LostPackets  int64
	OOOPackets   int64
	Bytes        int64
}

func (b Snapshot) Sub(a Snapshot) Delta {
	return Delta{
		DurationNsec: b.WhenNsec - a.WhenNsec,
		TxPackets:    b.LastSeqTx - a.LastSeqTx,
		RxPackets: (b.LastSeqRx - a.LastSeqRx) -
			(b.TotalLost - a.TotalLost) +
			(b.TotalOOO - a.TotalOOO),
		LostPackets: b.TotalLost - a.TotalLost,
		OOOPackets:  b.TotalOOO - a.TotalOOO,
		Bytes:       b.TotalBytesRx - a.TotalBytesRx,
	}
}

func (d Delta) String() string {
	return fmt.Sprintf("tx=%-6d rx=%-4d (%6d = %.1f%% loss) (%d OOO) (%4.1f Mbit/s)",
		d.TxPackets, d.RxPackets, d.LostPackets,
		float64(d.LostPackets)*100/float64(d.TxPackets),
		d.OOOPackets,
		float64(d.Bytes)*8*1e9/float64(d.DurationNsec)/1e6)
}

type TrafficGen struct {
	mu        sync.Mutex
	cur, prev Snapshot // snapshots used for rate control
	buf       []byte   // pre-generated packet buffer
	done      bool     // true if the test has completed

	onFirstPacket func() // function to call on first received packet

	// maxPackets is the max packets to receive (not send) before
	// ending the test. If it's zero, the test runs forever.
	maxPackets int64

	// nsPerPacket is the target average nanoseconds between packets.
	// It's initially zero, which means transmit as fast as the
	// caller wants to go.
	nsPerPacket int64

	// ppsHistory is the observed packets-per-second from recent
	// samples.
	ppsHistory [5]int64
}

// NewTrafficGen creates a new, initially locked, TrafficGen.
// Until Start() is called, Generate() will block forever.
func NewTrafficGen(onFirstPacket func()) *TrafficGen {
	t := TrafficGen{
		onFirstPacket: onFirstPacket,
	}

	// initially locked, until first Start()
	t.mu.Lock()

	return &t
}

// Start starts the traffic generator. It assumes mu is already locked,
// and unlocks it.
func (t *TrafficGen) Start(src, dst netip.Addr, bytesPerPacket int, maxPackets int64) {
	h12 := packet.ICMP4Header{
		IP4Header: packet.IP4Header{
			IPProto: ipproto.ICMPv4,
			IPID:    0,
			Src:     src,
			Dst:     dst,
		},
		Type: packet.ICMP4EchoRequest,
		Code: packet.ICMP4NoCode,
	}

	// ensure there's room for ICMP header plus sequence number
	if bytesPerPacket < ICMPMinSize+8 {
		log.Fatalf("bytesPerPacket must be > 24+8")
	}

	t.maxPackets = maxPackets

	payload := make([]byte, bytesPerPacket-ICMPMinSize)
	t.buf = packet.Generate(h12, payload)

	t.mu.Unlock()
}

func (t *TrafficGen) Snap() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.cur.WhenNsec = time.Now().UnixNano()
	return t.cur
}

func (t *TrafficGen) Running() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	return !t.done
}

// Generate produces the next packet in the sequence. It sleeps if
// it's too soon for the next packet to be sent.
//
// The generated packet is placed into buf at offset ofs, for compatibility
// with the wireguard-go conventions.
//
// The return value is the number of bytes generated in the packet, or 0
// if the test has finished running.
func (t *TrafficGen) Generate(b []byte, ofs int) int {
	t.mu.Lock()

	now := time.Now().UnixNano()
	if t.nsPerPacket == 0 || t.cur.timeAcc == 0 {
		t.cur.timeAcc = now - 1
	}
	if t.cur.timeAcc >= now {
		// too soon
		t.mu.Unlock()
		time.Sleep(time.Duration(t.cur.timeAcc-now) * time.Nanosecond)
		t.mu.Lock()

		now = t.cur.timeAcc
	}
	if t.done {
		t.mu.Unlock()
		return 0
	}

	t.cur.timeAcc += t.nsPerPacket
	t.cur.LastSeqTx += 1
	t.cur.WhenNsec = now
	seq := t.cur.LastSeqTx

	t.mu.Unlock()

	copy(b[ofs:], t.buf)
	binary.BigEndian.PutUint64(
		b[ofs+ICMPMinSize:ofs+ICMPMinSize+8],
		uint64(seq))

	return len(t.buf)
}

// GotPacket processes a packet that came back on the receive side.
func (t *TrafficGen) GotPacket(b []byte, ofs int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	s := &t.cur
	seq := int64(binary.BigEndian.Uint64(
		b[ofs+ICMPMinSize : ofs+ICMPMinSize+8]))
	if seq > s.LastSeqRx {
		if s.LastSeqRx > 0 {
			// only count lost packets after the very first
			// successful one.
			s.TotalLost += seq - s.LastSeqRx - 1
		}
		s.LastSeqRx = seq
	} else {
		s.TotalOOO += 1
	}

	// +1 packet since we only start counting after the first one
	if t.maxPackets > 0 && s.LastSeqRx >= t.maxPackets+1 {
		t.done = true
	}
	s.TotalBytesRx += int64(len(b) - ofs)

	f := t.onFirstPacket
	t.onFirstPacket = nil
	if f != nil {
		f()
	}
}

// Adjust tunes the transmit rate based on the received packets.
// The goal is to converge on the fastest transmit rate that still has
// minimal packet loss. Returns the new target rate in packets/sec.
//
// We need to play this guessing game in order to balance out tx and rx
// rates when there's a lossy network between them. Otherwise we can end
// up using 99% of the CPU to blast out transmitted packets and leaving only
// 1% to receive them, leading to a misleading throughput calculation.
//
// Call this function multiple times per second.
func (t *TrafficGen) Adjust() (pps int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	d := t.cur.Sub(t.prev)

	// don't adjust rate until the first full period *after* receiving
	// the first packet. This skips any handshake time in the underlying
	// transport.
	if t.prev.LastSeqRx == 0 || d.DurationNsec == 0 {
		t.prev = t.cur
		return 0 // no estimate yet, continue at max speed
	}

	pps = int64(d.RxPackets) * 1e9 / int64(d.DurationNsec)

	// We use a rate selection algorithm based loosely on TCP BBR.
	// Basically, we set the transmit rate to be a bit higher than
	// the best observed transmit rate in the last several time
	// periods. This guarantees some packet loss, but should converge
	// quickly on a rate near the sustainable maximum.
	bestPPS := pps
	for _, p := range t.ppsHistory {
		if p > bestPPS {
			bestPPS = p
		}
	}
	if pps > 0 && t.prev.WhenNsec > 0 {
		copy(t.ppsHistory[1:], t.ppsHistory[0:len(t.ppsHistory)-1])
		t.ppsHistory[0] = pps
	}
	if bestPPS > 0 {
		pps = bestPPS * 103 / 100
		t.nsPerPacket = int64(1e9 / pps)
	}
	t.prev = t.cur

	return pps
}

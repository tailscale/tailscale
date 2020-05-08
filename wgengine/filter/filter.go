// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package filter contains a stateful packet filter.
package filter

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"golang.org/x/time/rate"
	"tailscale.com/wgengine/packet"
)

type filterState struct {
	mu  sync.Mutex
	lru *lru.Cache // of tuple
}

// Filter is a stateful packet filter.
type Filter struct {
	matches Matches
	state   *filterState
}

// Response is a verdict: either a Drop, Accept, or noVerdict skip to
// continue processing.
type Response int

const (
	Drop Response = iota
	Accept
	noVerdict // Returned from subfilters to continue processing.
)

func (r Response) String() string {
	switch r {
	case Drop:
		return "Drop"
	case Accept:
		return "Accept"
	case noVerdict:
		return "noVerdict"
	default:
		return "???"
	}
}

// RunFlags controls the filter's debug log verbosity at runtime.
type RunFlags int

const (
	LogDrops RunFlags = 1 << iota
	LogAccepts
	HexdumpDrops
	HexdumpAccepts
)

type tuple struct {
	SrcIP   IP
	DstIP   IP
	SrcPort uint16
	DstPort uint16
}

const lruMax = 512 // max entries in UDP LRU cache

// MatchAllowAll matches all packets.
var MatchAllowAll = Matches{
	Match{[]NetPortRange{NetPortRangeAny}, []Net{NetAny}},
}

// NewAllowAll returns a packet filter that accepts everything.
func NewAllowAll() *Filter {
	return New(MatchAllowAll, nil)
}

// NewAllowNone returns a packet filter that rejects everything.
func NewAllowNone() *Filter {
	return New(nil, nil)
}

// New creates a new packet Filter with the given Matches rules.
// If shareStateWith is non-nil, the returned filter shares state
// with the previous one, to enable rules to be changed at runtime
// without breaking existing flows.
func New(matches Matches, shareStateWith *Filter) *Filter {
	var state *filterState
	if shareStateWith != nil {
		state = shareStateWith.state
	} else {
		state = &filterState{
			lru: lru.New(lruMax),
		}
	}
	f := &Filter{
		matches: matches,
		state:   state,
	}
	return f
}

func maybeHexdump(flag RunFlags, b []byte) string {
	if flag == 0 {
		return ""
	}
	return packet.Hexdump(b) + "\n"
}

// TODO(apenwarr): use a bigger bucket for specifically TCP SYN accept logging?
//   Logging is a quick way to record every newly opened TCP connection, but
//   we have to be cautious about flooding the logs vs letting people use
//   flood protection to hide their traffic. We could use a rate limiter in
//   the actual *filter* for SYN accepts, perhaps.
var acceptBucket = rate.NewLimiter(rate.Every(10*time.Second), 3)
var dropBucket = rate.NewLimiter(rate.Every(5*time.Second), 10)

func logRateLimit(runflags RunFlags, b []byte, q *packet.QDecode, r Response, why string) {
	if r == Drop && (runflags&LogDrops) != 0 && dropBucket.Allow() {
		var qs string
		if q == nil {
			qs = fmt.Sprintf("(%d bytes)", len(b))
		} else {
			qs = q.String()
		}
		log.Printf("Drop: %v %v %s\n%s", qs, len(b), why, maybeHexdump(runflags&HexdumpDrops, b))
	} else if r == Accept && (runflags&LogAccepts) != 0 && acceptBucket.Allow() {
		log.Printf("Accept: %v %v %s\n%s", q, len(b), why, maybeHexdump(runflags&HexdumpAccepts, b))
	}
}

func (f *Filter) RunIn(b []byte, q *packet.QDecode, rf RunFlags) Response {
	r := pre(b, q, rf)
	if r == Accept || r == Drop {
		// already logged
		return r
	}

	r, why := f.runIn(q)
	logRateLimit(rf, b, q, r, why)
	return r
}

func (f *Filter) RunOut(b []byte, q *packet.QDecode, rf RunFlags) Response {
	r := pre(b, q, rf)
	if r == Drop || r == Accept {
		// already logged
		return r
	}
	r, why := f.runOut(q)
	logRateLimit(rf, b, q, r, why)
	return r
}

func (f *Filter) runIn(q *packet.QDecode) (r Response, why string) {
	switch q.IPProto {
	case packet.ICMP:
		if q.IsEchoResponse() || q.IsError() {
			// ICMP responses are allowed.
			// TODO(apenwarr): consider using conntrack state.
			//  We could choose to reject all packets that aren't
			//  related to an existing ICMP-Echo, TCP, or UDP
			//  session.
			return Accept, "icmp response ok"
		} else if matchIPWithoutPorts(f.matches, q) {
			// If any port is open to an IP, allow ICMP to it.
			return Accept, "icmp ok"
		}
	case packet.TCP:
		// For TCP, we want to allow *outgoing* connections,
		// which means we want to allow return packets on those
		// connections. To make this restriction work, we need to
		// allow non-SYN packets (continuation of an existing session)
		// to arrive. This should be okay since a new incoming session
		// can't be initiated without first sending a SYN.
		// It happens to also be much faster.
		// TODO(apenwarr): Skip the rest of decoding in this path?
		if q.IPProto == packet.TCP && !q.IsTCPSyn() {
			return Accept, "tcp non-syn"
		}
		if matchIPPorts(f.matches, q) {
			return Accept, "tcp ok"
		}
	case packet.UDP:
		t := tuple{q.SrcIP, q.DstIP, q.SrcPort, q.DstPort}

		f.state.mu.Lock()
		_, ok := f.state.lru.Get(t)
		f.state.mu.Unlock()

		if ok {
			return Accept, "udp cached"
		}
		if matchIPPorts(f.matches, q) {
			return Accept, "udp ok"
		}
	default:
		return Drop, "Unknown proto"
	}
	return Drop, "no rules matched"
}

func (f *Filter) runOut(q *packet.QDecode) (r Response, why string) {
	if q.IPProto == packet.UDP {
		t := tuple{q.DstIP, q.SrcIP, q.DstPort, q.SrcPort}
		var ti interface{} = t // allocate once, rather than twice inside mutex

		f.state.mu.Lock()
		f.state.lru.Add(ti, ti)
		f.state.mu.Unlock()
	}
	return Accept, "ok out"
}

func pre(b []byte, q *packet.QDecode, rf RunFlags) Response {
	if len(b) == 0 {
		// wireguard keepalive packet, always permit.
		return Accept
	}
	if len(b) < 20 {
		logRateLimit(rf, b, nil, Drop, "too short")
		return Drop
	}
	q.Decode(b)

	if q.IPProto == packet.Junk {
		// Junk packets are dangerous; always drop them.
		logRateLimit(rf, b, q, Drop, "junk!")
		return Drop
	} else if q.IPProto == packet.Fragment {
		// Fragments after the first always need to be passed through.
		// Very small fragments are considered Junk by QDecode.
		logRateLimit(rf, b, q, Accept, "fragment")
		return Accept
	}

	return noVerdict
}

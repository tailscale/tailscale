// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"errors"
	"log"
	"math/rand/v2"
	"net/netip"
	"time"

	"tailscale.com/util/mak"
)

const (
	One2OneNAT NAT = "one2one"
	EasyNAT    NAT = "easy"   // address+port filtering
	EasyAFNAT  NAT = "easyaf" // address filtering (not port)
	HardNAT    NAT = "hard"
)

// IPPool is the interface that a NAT implementation uses to get information
// about a network.
//
// Outside of tests, this is typically a *network.
type IPPool interface {
	// WANIP returns the primary WAN IP address.
	//
	// TODO: add another method for networks with multiple WAN IP addresses.
	WANIP() netip.Addr

	// SoleLanIP reports whether this network has a sole LAN client
	// and if so, its IP address.
	SoleLANIP() (_ netip.Addr, ok bool)

	// IsPublicPortUsed reports whether the provided WAN IP+port is in use by
	// anything. (In particular, the NAT-PMP/etc port mappers might have taken
	// a port.) Implementations should check this before allocating a port,
	// and then they should report IsPublicPortUsed themselves for that port.
	IsPublicPortUsed(netip.AddrPort) bool
}

// newTableFunc is a constructor for a NAT table.
// The provided IPPool is typically (outside of tests) a *network.
type newTableFunc func(IPPool) (NATTable, error)

// NAT is a type of NAT that's known to natlab.
//
// For example, "easy" for Linux-style NAT, "hard" for FreeBSD-style NAT, etc.
type NAT string

// natTypes are the known NAT types.
var natTypes = map[NAT]newTableFunc{}

// registerNATType registers a NAT type.
func registerNATType(name NAT, f newTableFunc) {
	if _, ok := natTypes[name]; ok {
		panic("duplicate NAT type: " + name)
	}
	natTypes[name] = f
}

// NATTable is what a NAT implementation is expected to do.
//
// This project tests Tailscale as it faces various combinations various NAT
// implementations (e.g. Linux easy style NAT vs FreeBSD hard/endpoint dependent
// NAT vs Cloud 1:1 NAT, etc)
//
// Implementations of NATTable need not handle concurrency; the natlab serializes
// all calls into a NATTable.
//
// The provided `at` value will typically be time.Now, except for tests.
// Implementations should not use real time and should only compare
// previously provided time values.
type NATTable interface {
	// PickOutgoingSrc returns the source address to use for an outgoing packet.
	//
	// The result should either be invalid (to drop the packet) or a WAN (not
	// private) IP address.
	//
	// Typically, the src is a LAN source IP address, but it might also be a WAN
	// IP address if the packet is being forwarded for a source machine that has
	// a public IP address.
	PickOutgoingSrc(src, dst netip.AddrPort, at time.Time) (wanSrc netip.AddrPort)

	// PickIncomingDst returns the destination address to use for an incoming
	// packet. The incoming src address is always a public WAN IP.
	//
	// The result should either be invalid (to drop the packet) or the IP
	// address of a machine on the local network address, usually a private
	// LAN IP.
	PickIncomingDst(src, dst netip.AddrPort, at time.Time) (lanDst netip.AddrPort)

	// IsPublicPortUsed reports whether the provided WAN IP+port is in use by
	// anything. The port mapper uses this to avoid grabbing an in-use port.
	IsPublicPortUsed(netip.AddrPort) bool
}

// oneToOneNAT is a 1:1 NAT, like a typical EC2 VM.
type oneToOneNAT struct {
	lanIP netip.Addr
	wanIP netip.Addr
}

func init() {
	registerNATType(One2OneNAT, func(p IPPool) (NATTable, error) {
		lanIP, ok := p.SoleLANIP()
		if !ok {
			return nil, errors.New("can't use one2one NAT type on networks other than single-node networks")
		}
		return &oneToOneNAT{lanIP: lanIP, wanIP: p.WANIP()}, nil
	})
}

func (n *oneToOneNAT) PickOutgoingSrc(src, dst netip.AddrPort, at time.Time) (wanSrc netip.AddrPort) {
	return netip.AddrPortFrom(n.wanIP, src.Port())
}

func (n *oneToOneNAT) PickIncomingDst(src, dst netip.AddrPort, at time.Time) (lanDst netip.AddrPort) {
	return netip.AddrPortFrom(n.lanIP, dst.Port())
}

func (n *oneToOneNAT) IsPublicPortUsed(netip.AddrPort) bool {
	return true // all ports are owned by the 1:1 NAT
}

type srcDstTuple struct {
	src netip.AddrPort
	dst netip.AddrPort
}

type hardKeyIn struct {
	wanPort uint16
	src     netip.AddrPort
}

type portMappingAndTime struct {
	port uint16
	at   time.Time
}

type lanAddrAndTime struct {
	lanAddr netip.AddrPort
	at      time.Time
}

// hardNAT is an "Endpoint Dependent" NAT, like FreeBSD/pfSense/OPNsense.
// This is shown as "MappingVariesByDestIP: true" by netcheck, and what
// Tailscale calls "Hard NAT".
type hardNAT struct {
	pool  IPPool
	wanIP netip.Addr

	out map[srcDstTuple]portMappingAndTime
	in  map[hardKeyIn]lanAddrAndTime
}

func init() {
	registerNATType(HardNAT, func(p IPPool) (NATTable, error) {
		return &hardNAT{pool: p, wanIP: p.WANIP()}, nil
	})
}

func (n *hardNAT) IsPublicPortUsed(ap netip.AddrPort) bool {
	if ap.Addr() != n.wanIP {
		return false
	}
	for k := range n.in {
		if k.wanPort == ap.Port() {
			return true
		}
	}
	return false
}

func (n *hardNAT) PickOutgoingSrc(src, dst netip.AddrPort, at time.Time) (wanSrc netip.AddrPort) {
	ko := srcDstTuple{src, dst}
	if pm, ok := n.out[ko]; ok {
		// Existing flow.
		// TODO: bump timestamp
		return netip.AddrPortFrom(n.wanIP, pm.port)
	}

	// No existing mapping exists. Create one.

	// TODO: clean up old expired mappings

	// Instead of proper data structures that would be efficient, we instead
	// just loop a bunch and look for a free port. This project is only used
	// by tests and doesn't care about performance, this is good enough.
	for {
		port := rand.N(uint16(32<<10)) + 32<<10 // pick some "ephemeral" port
		if n.pool.IsPublicPortUsed(netip.AddrPortFrom(n.wanIP, port)) {
			continue
		}

		ki := hardKeyIn{wanPort: port, src: dst}
		if _, ok := n.in[ki]; ok {
			// Port already in use.
			continue
		}
		mak.Set(&n.in, ki, lanAddrAndTime{lanAddr: src, at: at})
		mak.Set(&n.out, ko, portMappingAndTime{port: port, at: at})
		return netip.AddrPortFrom(n.wanIP, port)
	}
}

func (n *hardNAT) PickIncomingDst(src, dst netip.AddrPort, at time.Time) (lanDst netip.AddrPort) {
	if dst.Addr() != n.wanIP {
		return netip.AddrPort{} // drop; not for us. shouldn't happen if natlabd routing isn't broken.
	}
	ki := hardKeyIn{wanPort: dst.Port(), src: src}
	if pm, ok := n.in[ki]; ok {
		// Existing flow.
		return pm.lanAddr
	}
	return netip.AddrPort{} // drop; no mapping
}

// easyNAT is an "Endpoint Independent" NAT, like Linux and most home routers
// (many of which are Linux).
//
// This is shown as "MappingVariesByDestIP: false" by netcheck, and what
// Tailscale calls "Easy NAT".
//
// Unlike Linux, this implementation is capped at 32k entries and doesn't resort
// to other allocation strategies when all 32k WAN ports are taken.
type easyNAT struct {
	pool    IPPool
	wanIP   netip.Addr
	out     map[netip.AddrPort]portMappingAndTime
	in      map[uint16]lanAddrAndTime
	lastOut map[srcDstTuple]time.Time // (lan:port, wan:port) => last packet out time
}

func init() {
	registerNATType(EasyNAT, func(p IPPool) (NATTable, error) {
		return &easyNAT{pool: p, wanIP: p.WANIP()}, nil
	})
}

func (n *easyNAT) IsPublicPortUsed(ap netip.AddrPort) bool {
	if ap.Addr() != n.wanIP {
		return false
	}
	_, ok := n.in[ap.Port()]
	return ok
}

func (n *easyNAT) PickOutgoingSrc(src, dst netip.AddrPort, at time.Time) (wanSrc netip.AddrPort) {
	mak.Set(&n.lastOut, srcDstTuple{src, dst}, at)
	if pm, ok := n.out[src]; ok {
		// Existing flow.
		// TODO: bump timestamp
		return netip.AddrPortFrom(n.wanIP, pm.port)
	}

	// Loop through all 32k high (ephemeral) ports, starting at a random
	// position and looping back around to the start.
	start := rand.N(uint16(32 << 10))
	for off := range uint16(32 << 10) {
		port := 32<<10 + (start+off)%(32<<10)
		if _, ok := n.in[port]; !ok {
			wanAddr := netip.AddrPortFrom(n.wanIP, port)
			if n.pool.IsPublicPortUsed(wanAddr) {
				continue
			}

			// Found a free port.
			mak.Set(&n.out, src, portMappingAndTime{port: port, at: at})
			mak.Set(&n.in, port, lanAddrAndTime{lanAddr: src, at: at})
			return wanAddr
		}
	}
	return netip.AddrPort{} // failed to allocate a mapping; TODO: fire an alert?
}

func (n *easyNAT) PickIncomingDst(src, dst netip.AddrPort, at time.Time) (lanDst netip.AddrPort) {
	if dst.Addr() != n.wanIP {
		return netip.AddrPort{} // drop; not for us. shouldn't happen if natlabd routing isn't broken.
	}
	lanDst = n.in[dst.Port()].lanAddr

	// Stateful firewall: drop incoming packets that don't have traffic out.
	// TODO(bradfitz): verify Linux does this in the router code, not in the NAT code.
	if t, ok := n.lastOut[srcDstTuple{lanDst, src}]; !ok || at.Sub(t) > 300*time.Second {
		log.Printf("Drop incoming packet from %v to %v; no recent outgoing packet", src, dst)
		return netip.AddrPort{}
	}

	return lanDst
}

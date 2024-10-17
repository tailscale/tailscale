// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"log"
	"math/rand/v2"
	"net/netip"
	"time"

	"tailscale.com/util/mak"
)

// easyAFNAT is an "Endpoint Independent" NAT, like Linux and most home routers
// (many of which are Linux), but with only address filtering, not address+port
// filtering.
//
// James says these are used by "anyone with “voip helpers” turned on"
// "which is a lot of home modem routers" ... "probably like most of the zyxel
// type things".
type easyAFNAT struct {
	pool    IPPool
	wanIP   netip.Addr
	out     map[netip.Addr]portMappingAndTime
	in      map[uint16]lanAddrAndTime
	lastOut map[srcAPDstAddrTuple]time.Time // (lan:port, wan:port) => last packet out time
}

type srcAPDstAddrTuple struct {
	src netip.AddrPort
	dst netip.Addr
}

func init() {
	registerNATType(EasyAFNAT, func(p IPPool) (NATTable, error) {
		return &easyAFNAT{pool: p, wanIP: p.WANIP()}, nil
	})
}

func (n *easyAFNAT) IsPublicPortUsed(ap netip.AddrPort) bool {
	if ap.Addr() != n.wanIP {
		return false
	}
	_, ok := n.in[ap.Port()]
	return ok
}

func (n *easyAFNAT) PickOutgoingSrc(src, dst netip.AddrPort, at time.Time) (wanSrc netip.AddrPort) {
	mak.Set(&n.lastOut, srcAPDstAddrTuple{src, dst.Addr()}, at)
	if pm, ok := n.out[src.Addr()]; ok {
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
			mak.Set(&n.out, src.Addr(), portMappingAndTime{port: port, at: at})
			mak.Set(&n.in, port, lanAddrAndTime{lanAddr: src, at: at})
			return wanAddr
		}
	}
	return netip.AddrPort{} // failed to allocate a mapping; TODO: fire an alert?
}

func (n *easyAFNAT) PickIncomingDst(src, dst netip.AddrPort, at time.Time) (lanDst netip.AddrPort) {
	if dst.Addr() != n.wanIP {
		return netip.AddrPort{} // drop; not for us. shouldn't happen if natlabd routing isn't broken.
	}
	lanDst = n.in[dst.Port()].lanAddr

	// Stateful firewall: drop incoming packets that don't have traffic out.
	// TODO(bradfitz): verify Linux does this in the router code, not in the NAT code.
	if t, ok := n.lastOut[srcAPDstAddrTuple{lanDst, src.Addr()}]; !ok || at.Sub(t) > 300*time.Second {
		log.Printf("Drop incoming packet from %v to %v; no recent outgoing packet", src, dst)
		return netip.AddrPort{}
	}

	return lanDst
}

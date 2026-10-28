// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/net/batching"
)

// A run of packets on one pair within a receive batch counts towards opening the pair as a whole, packets from unknown senders or without a local address do not count, and nothing happens while connected sockets are closed.
func TestLocalPairsCountsRuns(t *testing.T) {
	c := newConn(t.Logf)
	src := netip.MustParseAddrPort("127.0.0.1:9") // nothing is sent to it; opening a pair only binds and connects
	local := netip.MustParseAddr("127.0.0.1")
	pkt := batching.ReceivedPacket{Size: 1000, Source: src, Local: local}
	known := &endpoint{}
	var lp localPairs

	lp.note(c, pkt, known) // no set: counted, then dropped by flush
	lp.flush(c)

	pc, err := (&net.ListenConfig{Control: reusePortControl(nil)}).ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// A Reader that takes the socket and never reads it: this test is about when a pair opens, not what it carries.
	cs := conn.NewConnectedSockets(conn.ConnectedConfig{Port: pc.LocalAddr().(*net.UDPAddr).Port, OpenAfter: 3000,
		Reader: func(conn.ConnectedReadFunc, int, int) bool { return true }})
	if cs == nil {
		t.Skip("no connected sockets on this platform")
	}
	defer cs.Close()
	c.connected4.Store(cs)
	defer c.connected4.Store(nil)

	noLocal := pkt
	noLocal.Local = netip.Addr{}
	for range 5 {
		lp.note(c, pkt, nil)       // not a known peer
		lp.note(c, noLocal, known) // no local address to open a pair for
	}
	lp.flush(c)
	if lp.openSrc.IsValid() {
		t.Fatal("a pair opened from packets that should not count")
	}

	lp.note(c, pkt, known)
	lp.note(c, pkt, known)
	lp.flush(c)
	if lp.openSrc.IsValid() {
		t.Fatal("the pair opened after 2000 of its 3000 bytes")
	}
	lp.note(c, pkt, known)
	lp.flush(c)
	if lp.openSrc != src || lp.openLocal != local {
		t.Fatalf("after 3000 bytes the last open pair is %v -> %v; want %v -> %v", lp.openSrc, lp.openLocal, src, local)
	}
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package stunserver

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/net/stun"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/must"
)

// TestReplySourceAddr verifies that a response is sent from the address
// the request was sent to. It sends from 127.0.0.1 to the server at
// 127.0.0.2 (all of 127/8 is local on Linux); without pktinfo the kernel
// would reply from 127.0.0.1 instead. See the tests in net/pktinfo for the
// negative control and the v4-only socket case.
func TestReplySourceAddr(t *testing.T) {
	// Listen always creates a dual-stack socket, which needs IPv6.
	if c, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
		if !cibuild.On() {
			t.Skipf("IPv6 not supported: %v", err)
		}
		t.Fatalf("IPv6 not supported: %v", err)
	} else {
		c.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx)
	must.Do(s.Listen(":0"))
	if !s.pktInfo {
		t.Fatal("pktinfo not enabled")
	}
	go s.Serve()
	port := uint16(s.LocalAddr().(*net.UDPAddr).Port)
	serverAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), port)

	c := must.Get(net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}))
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	txid := stun.NewTxID()
	must.Get(c.WriteToUDPAddrPort(stun.Request(txid), serverAddr))

	var buf [1500]byte
	n, from, err := c.ReadFromUDPAddrPort(buf[:])
	if err != nil {
		t.Fatalf("reading STUN response: %v", err)
	}
	if from != serverAddr {
		t.Errorf("response came from %v; want %v", from, serverAddr)
	}
	tid, mapped, err := stun.ParseResponse(buf[:n])
	if err != nil {
		t.Fatalf("parsing STUN response: %v", err)
	}
	if tid != txid {
		t.Errorf("wrong transaction ID")
	}
	clientAddr := c.LocalAddr().(*net.UDPAddr).AddrPort()
	if mapped != clientAddr {
		t.Errorf("mapped address = %v; want %v", mapped, clientAddr)
	}
}

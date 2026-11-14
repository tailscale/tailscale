// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tstest/natlab/vmtest"
)

// pingOnce reports whether a single tta ping (4 echo requests) from n to ip
// gets a reply.
func pingOnce(t *testing.T, n *vmtest.Node, ip netip.Addr) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://unused/ping?host="+ip.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := n.Agent().HTTPClient.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	return res.StatusCode == 200
}

// tswgDatagram is a datagram received by tta on a socket shared with tswg.
type tswgDatagram struct {
	From netip.AddrPort
	Data []byte
}

// isWireGuardMessage reports whether b looks like a WireGuard message.
func isWireGuardMessage(b []byte) bool {
	return len(b) >= 4 && b[0] >= 1 && b[0] <= 4 && b[1] == 0 && b[2] == 0 && b[3] == 0
}

// checkNoWireGuardLeaked fails the test if any of dgs, received in
// userspace on node i's shared socket, is a WireGuard message.
func (p *tswgPair) checkNoWireGuardLeaked(i int, dgs []tswgDatagram) {
	p.t.Helper()
	for _, dg := range dgs {
		if isWireGuardMessage(dg.Data) {
			p.t.Errorf("[%s] WireGuard message (type %d, %d bytes) from %v leaked to userspace",
				p.nodes[i].Name(), dg.Data[0], len(dg.Data), dg.From)
		}
	}
}

// TestTSWGGokrazySharedSocket checks that a tswg device can share a UDP
// socket with userspace, as tailscaled's magicsock will: tta opens the
// socket and passes its fd to the device. The tunnel must work over it,
// non-WireGuard datagrams (disco, STUN) must reach userspace with the
// sender's shared socket as their source, no WireGuard messages may leak to
// userspace, and closing the socket must detach it so that a new one can
// take its place.
func TestTSWGGokrazySharedSocket(t *testing.T) {
	testTSWGSharedSocket(t, vmtest.Gokrazy)
}

// TestTSWGUbuntuSharedSocket is like TestTSWGGokrazySharedSocket, but on
// Ubuntu 24.04's stock 6.8 kernel, which exercises the compat paths.
func TestTSWGUbuntuSharedSocket(t *testing.T) {
	testTSWGSharedSocket(t, vmtest.Ubuntu2404)
}

func testTSWGSharedSocket(t *testing.T, osImg vmtest.OSImage) {
	p := newTSWGPair(t, osImg)
	p.up(0)
	p.up(1)

	// The tunnel works over the shared sockets.
	p.ping(0, 1)
	for i, n := range p.nodes {
		d := p.show(i)
		if !d.UserSocket4 {
			t.Errorf("[%s] UserSocket4 = false, want true", n.Name())
		}
		checkTSWGDevice(t, n, d, p.keys[i].Public(), p.ports[i])
	}

	// Non-WireGuard datagrams sent from one shared socket arrive on the
	// other in userspace, from the same address the tunnel uses.
	p.checkNoWireGuardLeaked(1, p.recv(1))
	disco := append([]byte("TS\xf0\x9f\x92\xac"), "fake disco ping"...)
	stun := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	for _, b := range [][]byte{disco, stun} {
		tta(t, p.nodes[0], "POST", "/tswg/sock-send?dev=tsw0&to="+p.lanAddr(1).String(), b)
	}
	var got []tswgDatagram
	deadline := time.Now().Add(10 * time.Second)
	for len(got) < 2 && time.Now().Before(deadline) {
		got = append(got, p.recv(1)...)
		time.Sleep(200 * time.Millisecond)
	}
	p.checkNoWireGuardLeaked(1, got)
	for _, want := range [][]byte{disco, stun} {
		found := false
		for _, dg := range got {
			if bytes.Equal(dg.Data, want) {
				found = true
				if dg.From != p.lanAddr(0) {
					t.Errorf("datagram %q came from %v, want %v (the sender's shared socket)", want, dg.From, p.lanAddr(0))
				}
			}
		}
		if !found {
			t.Errorf("datagram %q not received in userspace; got %d datagrams: %+v", want, len(got), got)
		}
	}

	// The tunnel still works, and still nothing leaks.
	p.ping(0, 1)
	p.checkNoWireGuardLeaked(1, p.recv(1))

	// Closing the shared socket detaches it from the device, which then
	// has no socket at all, so the tunnel stops working.
	tta(t, p.nodes[1], "POST", "/tswg/sock-close?dev=tsw0", nil)
	if d := p.show(1); d.UserSocket4 {
		t.Errorf("[%s] after closing the socket, UserSocket4 = true, want false", p.nodes[1].Name())
	}
	if !p.pingFails(0, 1) {
		t.Errorf("ping over the tunnel succeeded after %s closed its socket", p.nodes[1].Name())
	}

	// A new shared socket takes its place, and the tunnel works again.
	p.up(1)
	if d := p.show(1); !d.UserSocket4 {
		t.Errorf("[%s] after reattaching, UserSocket4 = false, want true", p.nodes[1].Name())
	}
	p.ping(0, 1)
	p.checkNoWireGuardLeaked(1, p.recv(1))
}

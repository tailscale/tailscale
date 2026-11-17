// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"net/url"
	"testing"

	"tailscale.com/tstest/natlab/vmtest"
)

// TestTSWGGokrazyNoRoam checks tswg's per-peer no-roam flag. Node 1 moves
// its shared socket to a new port, so that its packets reach node 2 from a
// new address. Without the flag, node 2 roams to that address, as upstream
// WireGuard does. With it, node 2 keeps the endpoint it was given (so the
// tunnel breaks, since nothing listens there anymore) until userspace sets
// a new one, as tailscaled's disco will.
func TestTSWGGokrazyNoRoam(t *testing.T) {
	testTSWGNoRoam(t, vmtest.Gokrazy)
}

// TestTSWGUbuntuNoRoam is like TestTSWGGokrazyNoRoam, but on Ubuntu
// 24.04's stock 6.8 kernel.
func TestTSWGUbuntuNoRoam(t *testing.T) {
	testTSWGNoRoam(t, vmtest.Ubuntu2404)
}

func testTSWGNoRoam(t *testing.T, osImg vmtest.OSImage) {
	p := newTSWGPair(t, osImg)
	p.up(0)
	p.up(1)
	p.ping(0, 1)
	if p.peer(1).NoRoam {
		t.Fatalf("NoRoam = true by default, want false")
	}

	// With roaming (the default), node 2 follows node 1 to a new port.
	p.ports[0] = 51821
	p.up(0)
	p.ping(0, 1)
	if got, want := p.peer(1).Endpoint, p.lanAddr(0); got != want {
		t.Errorf("with roaming, node 2's endpoint for node 1 = %v, want %v", got, want)
	}

	// With roaming disabled, node 2 stays put when node 1 moves again,
	// even though it receives authenticated packets from the new address,
	// so the tunnel breaks.
	pinned := p.lanAddr(0)
	p.setPeer(1, url.Values{"no-roam": {"1"}})
	if !p.peer(1).NoRoam {
		t.Fatalf("NoRoam = false after setting it")
	}
	p.ports[0] = 51822
	p.up(0)
	if !p.pingFails(0, 1) {
		t.Errorf("ping succeeded, but node 2 should have kept sending to the old port")
	}
	if got := p.peer(1).Endpoint; got != pinned {
		t.Errorf("with no-roam, node 2's endpoint for node 1 = %v, want it pinned at %v", got, pinned)
	}

	// Userspace can still set the endpoint explicitly, which fixes the
	// tunnel, and the flag sticks.
	p.setPeer(1, url.Values{"endpoint": {p.lanAddr(0).String()}})
	p.ping(0, 1)
	peer := p.peer(1)
	if got, want := peer.Endpoint, p.lanAddr(0); got != want {
		t.Errorf("after setting it, node 2's endpoint for node 1 = %v, want %v", got, want)
	}
	if !peer.NoRoam {
		t.Errorf("NoRoam = false after setting the endpoint, want true")
	}
}

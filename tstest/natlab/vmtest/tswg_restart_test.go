// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"sync"
	"testing"
	"time"

	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestTSWGTailscaledBothRestart restarts tailscaled on both nodes at once,
// several times, and checks that the tunnel works again soon after both
// are back. Both nodes lose their sessions at the same moment, and each
// learns the other's new disco key while its own kernel device is new.
func TestTSWGTailscaledBothRestart(t *testing.T) {
	f := newTSWGTailscaled(t, vnet.EasyNAT)
	f.env.LANPing(f.nodes[0], f.ip(f.nodes[1]))
	for round := range 5 {
		f.restartAll(nil)
		for _, n := range f.nodes {
			f.waitKernelReady(n)
		}
		f.waitTunnel(round)
	}
}

// TestTSWGTailscaledModeSwitch switches both nodes between TUN mode
// (wireguard-go) and kernel mode at the same time, several times each
// way, as when a fleet loads or unloads tswg, and checks that the tunnel
// works again soon after each switch.
func TestTSWGTailscaledModeSwitch(t *testing.T) {
	testTSWGTailscaledModeSwitch(t, tswgTailscaledOpts{tunNodes: 2}, false)
}

// TestTSWGTailscaledModeSwitchRolling is like TestTSWGTailscaledModeSwitch,
// but with both nodes on one LAN, switched one after the other, as the
// natlab benchmark does (which once lost the tunnel for over 10 seconds
// after doing so).
func TestTSWGTailscaledModeSwitchRolling(t *testing.T) {
	testTSWGTailscaledModeSwitch(t, tswgTailscaledOpts{tunNodes: 2, sameLAN: true}, true)
}

func testTSWGTailscaledModeSwitch(t *testing.T, opts tswgTailscaledOpts, rolling bool) {
	f := newTSWGTailscaledOpts(t, vnet.EasyNAT, opts)
	f.env.LANPing(f.nodes[0], f.ip(f.nodes[1]))
	for round := range 6 {
		kernel := round%2 == 0
		restart := f.restartAll
		if rolling {
			restart = f.restartEach
		}
		restart(func(n *vmtest.Node) {
			if kernel {
				tta(t, n, "POST", "/tswg/load", f.ko)
			} else {
				tta(t, n, "POST", "/tswg/unload", nil)
			}
		})
		for _, n := range f.nodes {
			if kernel {
				f.waitKernelReady(n)
			} else if _, err := f.show(n); err == nil {
				t.Fatalf("[%s] still has a kernel device after unloading tswg", n.Name())
			}
		}
		f.waitTunnel(round)
	}
}

// restartAll restarts tailscaled on all nodes at once, after calling
// before (if non-nil) on each, also at once.
func (f *tswgTailscaled) restartAll(before func(*vmtest.Node)) {
	var wg sync.WaitGroup
	for _, n := range f.nodes {
		wg.Go(func() {
			if before != nil {
				before(n)
			}
			f.env.RestartTailscaled(n)
		})
	}
	wg.Wait()
}

// restartEach is like restartAll, but one node after the other.
func (f *tswgTailscaled) restartEach(before func(*vmtest.Node)) {
	for _, n := range f.nodes {
		if before != nil {
			before(n)
		}
		f.env.RestartTailscaled(n)
	}
}

// waitTunnel checks that pings work both ways soon, failing the test if
// they don't within 10 seconds.
func (f *tswgTailscaled) waitTunnel(round int) {
	t := f.t
	t.Helper()
	n1, n2 := f.nodes[0], f.nodes[1]
	ip1, ip2 := f.ip(n1), f.ip(n2)

	// Each pingOnce is 4 pings a second apart, so it takes 3 seconds
	// when the tunnel works.
	start := time.Now()
	for !pingOnce(t, n1, ip2) || !pingOnce(t, n2, ip1) {
		if time.Since(start) > 30*time.Second {
			for _, n := range f.nodes {
				if d, err := f.show(n); err == nil {
					t.Logf("[%s] kernel peers: %+v", n.Name(), d.Peers)
				}
			}
			t.Fatalf("round %d: no traffic through the tunnel 30s after the restarts", round)
		}
	}
	d := time.Since(start).Round(100 * time.Millisecond)
	t.Logf("round %d: pings both ways took %v after the restarts", round, d)
	if d > 10*time.Second {
		t.Errorf("round %d: tunnel took %v to come back", round, d)
	}
}

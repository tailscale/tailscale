// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"fmt"
	"maps"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/ipproto"
)

var nilPacket *packet.Parsed // nil packet to perform actions against

// mkTuple wraps flowtrack.MakeTuple with the UDP proto.
func mkTuple(src, dst string) flowtrack.Tuple {
	return flowtrack.MakeTuple(
		ipproto.UDP,
		netip.MustParseAddrPort(src),
		netip.MustParseAddrPort(dst),
	)
}

func mkFlowWithActions(fromTun, fromWG flowtrack.Tuple) (FlowData, *int, *int) {
	var tunCalls, wgCalls int
	fd := mkFlow(fromTun, fromWG)
	fd.FromTun.Action = func(_ *packet.Parsed) { tunCalls++ }
	fd.FromWG.Action = func(_ *packet.Parsed) { wgCalls++ }
	return fd, &tunCalls, &wgCalls
}

func mkFlow(fromTun, fromWG flowtrack.Tuple) FlowData {
	return FlowData{
		FromTun: TupleAndAction{
			Tuple:  fromTun,
			Action: func(_ *packet.Parsed) {},
		},
		FromWG: TupleAndAction{
			Tuple:  fromWG,
			Action: func(_ *packet.Parsed) {},
		},
	}
}

func mkFlows(n int) []FlowData {
	flows := make([]FlowData, n)
	for i := range n {
		flows[i] = mkFlow(
			mkTuple(fmt.Sprintf("1.0.%d.%d:1000", (i>>8)&0xff, i&0xff), "2.0.0.1:80"),
			mkTuple(fmt.Sprintf("3.0.%d.%d:1000", (i>>8)&0xff, i&0xff), "4.0.0.1:80"),
		)
	}
	return flows
}

func assertFlowHit(t *testing.T, ft *FlowTable, dir Origin, tuple flowtrack.Tuple) PacketAction {
	t.Helper()
	return assertFlowLookup(t, ft, dir, tuple, true)
}

func assertFlowMiss(t *testing.T, ft *FlowTable, dir Origin, tuple flowtrack.Tuple) {
	t.Helper()
	assertFlowLookup(t, ft, dir, tuple, false)
}

func assertFlowLookup(t *testing.T, ft *FlowTable, dir Origin, tuple flowtrack.Tuple, wantHit bool) PacketAction {
	t.Helper()
	var action PacketAction
	var ok bool

	switch dir {
	case FromTun:
		action, ok = ft.LookupFromTunDevice(tuple)
	case FromWireGuard:
		action, ok = ft.LookupFromWireGuard(tuple)
	default:
		t.Fatalf("invalid direction: %v", dir)
	}

	if wantHit && !ok {
		t.Fatalf("expected flow hit for tuple: %v, dir: %v", tuple, dir)
	}
	if !wantHit && ok {
		t.Fatalf("expected flow miss for tuple: %v, dir: %v", tuple, dir)
	}

	if wantHit {
		return action
	}
	return nil
}

func TestFlowTable_NewFlow_Lookup(t *testing.T) {
	ft := NewFlowTable(0)

	// The tuples in both directions are defined by the caller.
	// The don't have to be mirror images of each other,
	// to account for intentional modifications, like NAT.
	fromTunTuple := mkTuple("1.2.3.4:1000", "4.3.2.1:80")
	fromWGTuple := mkTuple("4.3.2.2:80", "1.2.3.4:1000")

	flow1, tunCount1, wgCount1 := mkFlowWithActions(fromTunTuple, fromWGTuple)
	ft.NewFlow(flow1)

	// Test basic lookups, and perform actions on packet.
	assertFlowHit(t, ft, FromTun, fromTunTuple)(nilPacket)
	assertFlowHit(t, ft, FromWireGuard, fromWGTuple)(nilPacket)

	if *tunCount1 != 1 {
		t.Fatal("action for from-tun tuple key was not executed")
	}
	if *wgCount1 != 1 {
		t.Fatal("action for from-wg tuple key was not executed")
	}

	// Test tuple not found.
	notFoundTuple := mkTuple("1.2.3.4:1000", "4.0.4.4:80")
	assertFlowMiss(t, ft, FromTun, notFoundTuple)

	// Wrong direction is also not found.
	assertFlowMiss(t, ft, FromWireGuard, fromTunTuple)

	// Overwriting from-tun tuple removes the from-wg tuple as well.
	newFromWGTuple := mkTuple("9.9.9.9:99", "8.8.8.8:88")
	flow2 := mkFlow(fromTunTuple, newFromWGTuple)
	ft.NewFlow(flow2)
	assertFlowMiss(t, ft, FromWireGuard, fromWGTuple)

	// Overwriting the from-wg tuple removes the from-tun tuple as well.
	newFromTunTuple := mkTuple("8.8.8.8:88", "9.9.9.9:99")
	flow3 := mkFlow(newFromTunTuple, newFromWGTuple)
	ft.NewFlow(flow3)
	assertFlowMiss(t, ft, FromTun, fromTunTuple)
}

// TestFlowTable_OneReplacesTwo targets a specific case
// in which a single new flow replaces two existing flows
// because each tuple of the new flow matches one tuple
// of an existing flow.
func TestFlowTable_OneReplacesTwo(t *testing.T) {
	ft := NewFlowTable(0)

	tunTuple1 := mkTuple("1.2.3.4:1000", "4.3.2.1:80")
	wgTuple1 := mkTuple("4.3.2.2:80", "1.2.3.4:1000")
	flow1, tunCount1, wgCount1 := mkFlowWithActions(tunTuple1, wgTuple1)

	tunTuple2 := mkTuple("8.8.8.8:88", "9.9.9.9:99")
	wgTuple2 := mkTuple("9.9.9.9:99", "8.8.8.8:88")
	flow2, tunCount2, wgCount2 := mkFlowWithActions(tunTuple2, wgTuple2)

	// Install the first two flows.
	ft.NewFlow(flow1)
	ft.NewFlow(flow2)

	// Confirm they are properly installed through lookups.
	assertFlowHit(t, ft, FromTun, tunTuple1)
	assertFlowHit(t, ft, FromWireGuard, wgTuple1)
	assertFlowHit(t, ft, FromTun, tunTuple2)
	assertFlowHit(t, ft, FromWireGuard, wgTuple2)

	// flow3 tuples overlap with flow1 and flow2.
	flow3, tunCount3, wgCount3 := mkFlowWithActions(tunTuple1, wgTuple2)
	ft.NewFlow(flow3)

	// flow3 lookups hit on both of their tuples.
	tunAction3 := assertFlowHit(t, ft, FromTun, tunTuple1)
	wgAction3 := assertFlowHit(t, ft, FromWireGuard, wgTuple2)

	// The non-overlapping tuples from flow1 and flow2 should now miss.
	assertFlowMiss(t, ft, FromTun, tunTuple2)
	assertFlowMiss(t, ft, FromWireGuard, wgTuple1)

	// Perform both actions on a nil packet to bump counters.
	tunAction3(nilPacket)
	wgAction3(nilPacket)

	// Only flow3 counters should have been bumped.
	if *tunCount1 != 0 || *wgCount1 != 0 {
		t.Fatalf("flow1 counters (tun, wg), want: (0,0), got: (%d,%d)", *tunCount1, *wgCount1)
	}
	if *tunCount2 != 0 || *wgCount2 != 0 {
		t.Fatalf("flow2 counters (tun, wg), want: (0,0), got: (%d,%d)", *tunCount2, *wgCount2)
	}
	if *tunCount3 != 1 || *wgCount3 != 1 {
		t.Fatalf("flow3 counters (tun, wg), want: (1,1), got: (%d,%d)", *tunCount3, *wgCount3)
	}
}

func TestFlowTable_Eviction(t *testing.T) {
	// Table only has two spots.
	ft := NewFlowTable(2)
	aTun, aWG := mkTuple("3.0.0.1:1000", "3.0.0.2:80"), mkTuple("3.0.0.2:80", "3.0.0.1:1000")
	bTun, bWG := mkTuple("3.0.0.3:1000", "3.0.0.4:80"), mkTuple("3.0.0.4:80", "3.0.0.3:1000")
	cTun, cWG := mkTuple("3.0.0.5:1000", "3.0.0.6:80"), mkTuple("3.0.0.6:80", "3.0.0.5:1000")
	dTun, dWG := mkTuple("3.0.0.7:1000", "3.0.0.8:80"), mkTuple("3.0.0.8:80", "3.0.0.7:1000")

	a := mkFlow(aTun, aWG)
	b := mkFlow(bTun, bWG)
	c := mkFlow(cTun, cWG)
	d := mkFlow(dTun, dWG)

	// Install a and b.
	ft.NewFlow(a)
	ft.NewFlow(b)

	// Move a to the front from tun side, b is ready for eviction.
	assertFlowHit(t, ft, FromTun, aTun)

	// Install c.
	ft.NewFlow(c)

	// Check b is out.
	assertFlowMiss(t, ft, FromTun, bTun)
	assertFlowMiss(t, ft, FromWireGuard, bWG)

	// Check c is in.
	assertFlowHit(t, ft, FromTun, cTun)
	assertFlowHit(t, ft, FromWireGuard, cWG)

	// Move a to the front again, now from WG side.
	assertFlowHit(t, ft, FromWireGuard, aWG)

	// Install d.
	ft.NewFlow(d)

	// Check c is out.
	assertFlowMiss(t, ft, FromTun, cTun)
	assertFlowMiss(t, ft, FromWireGuard, cWG)

	// Check d is in.
	assertFlowHit(t, ft, FromTun, dTun)
	assertFlowHit(t, ft, FromWireGuard, dWG)
}

func syncSubtest(t *testing.T, name string, f func(*testing.T)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		synctest.Test(t, f)
	})
}

func TestFlowTable_removeIdle(t *testing.T) {
	type flowSpec struct {
		installAt   time.Duration // wall-clock time of install, from test start
		wantRemoved bool          // do we expect this flow to be removed by the sweep
	}

	tests := []struct {
		name               string
		idleTimeout        time.Duration
		maxRemovedPerSweep int
		flowSpecs          []flowSpec
		removalAt          time.Duration // wall-clock time of sweep, from test start
	}{
		{
			name:        "one-expired-flow",
			idleTimeout: 1 * time.Minute,
			flowSpecs: []flowSpec{
				{installAt: 0, wantRemoved: true}, // age at sweep = 120s
			},
			removalAt: 2 * time.Minute,
		},
		{
			name:        "one-not-expired-flow",
			idleTimeout: 1 * time.Minute,
			flowSpecs: []flowSpec{
				{installAt: 0, wantRemoved: false}, // age at sweep = 30s
			},
			removalAt: 30 * time.Second,
		},
		{
			name:        "two-flows-one-expired",
			idleTimeout: 1 * time.Minute,
			flowSpecs: []flowSpec{
				{installAt: 0, wantRemoved: true},                 // age at sweep = 75s
				{installAt: 30 * time.Second, wantRemoved: false}, // age at sweep = 45s
			},
			removalAt: 75 * time.Second,
		},
		{
			name:        "two-flows-both-expired",
			idleTimeout: 1 * time.Minute,
			flowSpecs: []flowSpec{
				{installAt: 0, wantRemoved: true},                // age at sweep = 120s
				{installAt: 30 * time.Second, wantRemoved: true}, // age at sweep = 90s
			},
			removalAt: 2 * time.Minute,
		},
		{
			// Both flows are time-expired, but maxRemovedPerSweep=1 caps removal at 1.
			// Flow 0 is at the back of the LRU (installed first) and is removed; flow 1 stays.
			name:               "two-flows-both-expired-but-max-count-equal-one",
			idleTimeout:        1 * time.Minute,
			maxRemovedPerSweep: 1,
			flowSpecs: []flowSpec{
				{installAt: 0, wantRemoved: true},                 // age at sweep = 120s, removed (under cap)
				{installAt: 30 * time.Second, wantRemoved: false}, // age at sweep = 90s, kept (cap reached)
			},
			removalAt: 2 * time.Minute,
		},
		{
			name:        "zero-idle-timeout-means-no-expiration",
			idleTimeout: 0,
			flowSpecs: []flowSpec{
				{installAt: 0, wantRemoved: false},
				{installAt: 30 * time.Second, wantRemoved: false},
			},
			removalAt: 2 * time.Minute,
		},
	}

	for _, tt := range tests {
		syncSubtest(t, tt.name, func(t *testing.T) {
			ft := NewFlowTable(
				0, // turn off LRU for these tests
				WithFlowIdleTimeout(tt.idleTimeout),
				WithMaxRemovedFlowsPerSweep(tt.maxRemovedPerSweep),
			)

			start := time.Now()
			flows := mkFlows(len(tt.flowSpecs))
			for i, spec := range tt.flowSpecs {
				time.Sleep(time.Until(start.Add(spec.installAt)))
				ft.NewFlow(flows[i])
			}

			var wantRemovedCount int
			for _, spec := range tt.flowSpecs {
				if spec.wantRemoved {
					wantRemovedCount++
				}
			}

			time.Sleep(time.Until(start.Add(tt.removalAt)))

			gotRemovedCount := ft.removeIdle(mono.Now())
			if wantRemovedCount != gotRemovedCount {
				t.Errorf("unexpected remove idle count: want %d, got %d", wantRemovedCount, gotRemovedCount)
			}

			for i, spec := range tt.flowSpecs {
				if spec.wantRemoved {
					assertFlowMiss(t, ft, FromTun, flows[i].FromTun.Tuple)
				} else {
					assertFlowHit(t, ft, FromTun, flows[i].FromTun.Tuple)
				}
			}
		})
	}

	syncSubtest(t, "lookup-resets-lastseen", func(t *testing.T) {
		ft := NewFlowTable(0, WithFlowIdleTimeout(time.Minute))
		flows := mkFlows(2)

		ft.NewFlow(flows[0])                                  // t=0 (flow 0 install)
		time.Sleep(30 * time.Second)                          //
		ft.NewFlow(flows[1])                                  // t=30s (flow 1 install)
		time.Sleep(60 * time.Second)                          //
		assertFlowHit(t, ft, FromTun, flows[0].FromTun.Tuple) // t=90s (flow 0 looked up, lastSeen bumped)
		time.Sleep(15 * time.Second)                          //

		if got := ft.removeIdle(mono.Now()); got != 1 {
			t.Errorf("removeIdle returned %d, want 1", got)
		}
		assertFlowHit(t, ft, FromTun, flows[0].FromTun.Tuple)
		assertFlowMiss(t, ft, FromTun, flows[1].FromTun.Tuple)
	})
}

// recordOnRemove returns an OnRemove that increments fired[name] when invoked.
// Used to verify OnRemove fires for the right flows the right number of times.
func recordOnRemove(fired map[string]int, name string) func() {
	return func() { fired[name]++ }
}

func TestFlowTable_OnRemove(t *testing.T) {
	tun1 := mkTuple("1.1.1.1:1000", "2.2.2.2:80")
	wg1 := mkTuple("2.2.2.2:80", "1.1.1.1:1000")
	tun2 := mkTuple("3.3.3.3:1000", "4.4.4.4:80")
	wg2 := mkTuple("4.4.4.4:80", "3.3.3.3:1000")

	t.Run("displacement", func(t *testing.T) {
		// fd2 collides with fd1 on the FromTun tuple; fd1 is displaced and
		// its OnRemove fires. fd2 stays installed and its OnRemove does not.
		ft := NewFlowTable(0)
		fired := map[string]int{}

		fd1 := mkFlow(tun1, wg1)
		fd1.OnRemove = recordOnRemove(fired, "fd1")
		ft.NewFlow(fd1)

		fd2 := mkFlow(tun1, wg2)
		fd2.OnRemove = recordOnRemove(fired, "fd2")
		ft.NewFlow(fd2)

		if want := (map[string]int{"fd1": 1}); !maps.Equal(fired, want) {
			t.Errorf("fired = %v, want %v", fired, want)
		}
	})

	t.Run("one-replaces-two", func(t *testing.T) {
		// fd3's FromTun matches fd1's, and fd3's FromWG matches fd2's. Both
		// fd1 and fd2 should be displaced and both OnRemoves should fire.
		ft := NewFlowTable(0)
		fired := map[string]int{}

		fd1 := mkFlow(tun1, wg1)
		fd1.OnRemove = recordOnRemove(fired, "fd1")
		ft.NewFlow(fd1)

		fd2 := mkFlow(tun2, wg2)
		fd2.OnRemove = recordOnRemove(fired, "fd2")
		ft.NewFlow(fd2)

		fd3 := mkFlow(tun1, wg2)
		fd3.OnRemove = recordOnRemove(fired, "fd3")
		ft.NewFlow(fd3)

		if want := (map[string]int{"fd1": 1, "fd2": 1}); !maps.Equal(fired, want) {
			t.Errorf("fired = %v, want %v", fired, want)
		}
	})

	t.Run("reinstall-same-tuples-fires-once", func(t *testing.T) {
		// Re-installing a flow with identical tuples from both directions
		// causes removeFlowLocked to be called twice (once from each direction).
		// Only one OnRemove should be called for the single flow.
		ft := NewFlowTable(0)
		fired := map[string]int{}

		fd1 := mkFlow(tun1, wg1)
		fd1.OnRemove = recordOnRemove(fired, "fd1")
		ft.NewFlow(fd1)

		fd2 := mkFlow(tun1, wg1) // identical tuples
		fd2.OnRemove = recordOnRemove(fired, "fd2")
		ft.NewFlow(fd2)

		if want := (map[string]int{"fd1": 1}); !maps.Equal(fired, want) {
			t.Errorf("fired = %v, want %v", fired, want)
		}
	})

	t.Run("capacity-eviction", func(t *testing.T) {
		// With capacity 1, installing fd2 evicts fd1 from the back of the
		// LRU; fd1's OnRemove fires.
		ft := NewFlowTable(1)
		fired := map[string]int{}

		fd1 := mkFlow(tun1, wg1)
		fd1.OnRemove = recordOnRemove(fired, "fd1")
		ft.NewFlow(fd1)

		fd2 := mkFlow(tun2, wg2)
		fd2.OnRemove = recordOnRemove(fired, "fd2")
		ft.NewFlow(fd2)

		if want := (map[string]int{"fd1": 1}); !maps.Equal(fired, want) {
			t.Errorf("fired = %v, want %v", fired, want)
		}
	})

	syncSubtest(t, "remove-idle", func(t *testing.T) {
		ft := NewFlowTable(0, WithFlowIdleTimeout(time.Minute))
		fired := map[string]int{}

		fd1 := mkFlow(tun1, wg1)
		fd1.OnRemove = recordOnRemove(fired, "fd1")
		ft.NewFlow(fd1)

		time.Sleep(2 * time.Minute) // advance synthetic clock past idleTimeout
		if got, want := ft.removeIdle(mono.Now()), 1; got != want {
			t.Errorf("removeIdle returned %d, want %d", got, want)
		}

		if want := (map[string]int{"fd1": 1}); !maps.Equal(fired, want) {
			t.Errorf("fired = %v, want %v", fired, want)
		}
	})

	t.Run("nil-onremove-no-panic", func(t *testing.T) {
		ft := NewFlowTable(0)

		ft.NewFlow(mkFlow(tun1, wg1)) // OnRemove unset
		ft.NewFlow(mkFlow(tun1, wg2)) // displaces the first flow
	})

	t.Run("runs-outside-table-lock", func(t *testing.T) {
		ft := NewFlowTable(0)

		var onRemoveRan bool
		fd1 := mkFlow(tun1, wg1)
		fd1.OnRemove = func() {
			// NewFlow is used here because we know it acquires the mutex,
			// So this will prove OnRemove() is called with the mutex released.
			ft.NewFlow(mkFlow(tun2, wg2))
			onRemoveRan = true
		}
		ft.NewFlow(fd1)

		// This should cause displacement of the first flow, and OnRemove to fire.
		ft.NewFlow(mkFlow(tun1, mkTuple("9.9.9.9:99", "8.8.8.8:88")))

		if !onRemoveRan {
			t.Errorf("OnRemove did not run")
		}
		// The new install should be visible.
		assertFlowHit(t, ft, FromTun, tun2)
	})
}

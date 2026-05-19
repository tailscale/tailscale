// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"net/netip"
	"testing"

	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
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

func mustInstallFlow(t *testing.T, ft *FlowTable, flow FlowData) {
	t.Helper()
	if err := ft.NewFlow(flow); err != nil {
		t.Fatalf("error installing flow: %v", err)
	}
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
	mustInstallFlow(t, ft, flow1)

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
	mustInstallFlow(t, ft, flow2)
	assertFlowMiss(t, ft, FromWireGuard, fromWGTuple)

	// Overwriting the from-wg tuple removes the from-tun tuple as well.
	newFromTunTuple := mkTuple("8.8.8.8:88", "9.9.9.9:99")
	flow3 := mkFlow(newFromTunTuple, newFromWGTuple)
	mustInstallFlow(t, ft, flow3)
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
	mustInstallFlow(t, ft, flow1)
	mustInstallFlow(t, ft, flow2)

	// Confirm they are properly installed through lookups.
	assertFlowHit(t, ft, FromTun, tunTuple1)
	assertFlowHit(t, ft, FromWireGuard, wgTuple1)
	assertFlowHit(t, ft, FromTun, tunTuple2)
	assertFlowHit(t, ft, FromWireGuard, wgTuple2)

	// flow3 tuples overlap with flow1 and flow2.
	flow3, tunCount3, wgCount3 := mkFlowWithActions(tunTuple1, wgTuple2)
	mustInstallFlow(t, ft, flow3)

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
	mustInstallFlow(t, ft, a)
	mustInstallFlow(t, ft, b)

	// Move a to the front from tun side, b is ready for eviction.
	assertFlowHit(t, ft, FromTun, aTun)

	// Install c.
	mustInstallFlow(t, ft, c)

	// Check b is out.
	assertFlowMiss(t, ft, FromTun, bTun)
	assertFlowMiss(t, ft, FromWireGuard, bWG)

	// Check c is in.
	assertFlowHit(t, ft, FromTun, cTun)
	assertFlowHit(t, ft, FromWireGuard, cWG)

	// Move a to the front again, now from WG side.
	assertFlowHit(t, ft, FromWireGuard, aWG)

	// Install d.
	mustInstallFlow(t, ft, d)

	// Check c is out.
	assertFlowMiss(t, ft, FromTun, cTun)
	assertFlowMiss(t, ft, FromWireGuard, cWG)

	// Check d is in.
	assertFlowHit(t, ft, FromTun, dTun)
	assertFlowHit(t, ft, FromWireGuard, dWG)
}

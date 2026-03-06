// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"errors"
	"net/netip"
	"testing"

	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

func TestFlowTable(t *testing.T) {
	ft := NewFlowTable(0)

	fwdTuple := flowtrack.MakeTuple(
		ipproto.UDP,
		netip.MustParseAddrPort("1.2.3.4:1000"),
		netip.MustParseAddrPort("4.3.2.1:80"),
	)
	// Reverse tuple is defined by caller. Doesn't have to be mirror image of fwd.
	// To account for intentional modifications, like NAT.
	revTuple := flowtrack.MakeTuple(
		ipproto.UDP,
		netip.MustParseAddrPort("4.3.2.2:80"),
		netip.MustParseAddrPort("1.2.3.4:1000"),
	)

	fwdAction, revAction := 0, 0
	fwdData := FlowData{
		Tuple:  fwdTuple,
		Action: func(_ *packet.Parsed) { fwdAction++ },
	}
	revData := FlowData{
		Tuple:  revTuple,
		Action: func(_ *packet.Parsed) { revAction++ },
	}

	// For this test setup, from the tun device will be "forward",
	// and from WG will be "reverse".
	if err := ft.NewFlowFromTunDevice(fwdData, revData); err != nil {
		t.Fatalf("got non-nil error for new flow from tun device")
	}

	// Test basic lookups.
	lookupFwd, err := ft.LookupFromTunDevice(fwdTuple)
	if err != nil {
		t.Fatalf("got non-nil error on first lookup from tun device")
	}
	lookupFwd.Action(nil)
	if fwdAction != 1 {
		t.Errorf("action for fwd tuple key was not executed")
	}

	lookupRev, err := ft.LookupFromWireGuard(revTuple)
	if err != nil {
		t.Fatalf("got non-nil error on first lookup from WireGuard")
	}
	lookupRev.Action(nil)
	if revAction != 1 {
		t.Errorf("action for rev tuple key was not executed")
	}

	// Test not found error.
	notFoundTuple := flowtrack.MakeTuple(
		ipproto.UDP,
		netip.MustParseAddrPort("1.2.3.4:1000"),
		netip.MustParseAddrPort("4.0.4.4:80"),
	)
	if _, err := ft.LookupFromTunDevice(notFoundTuple); !errors.Is(err, ErrFlowNotFound) {
		t.Errorf("expected ErrFlowNotFound for foreign tuple")
	}

	// Wrong direction is also not found.
	if _, err := ft.LookupFromWireGuard(fwdTuple); !errors.Is(err, ErrFlowNotFound) {
		t.Errorf("expected ErrFlowNotFound for wrong direction tuple")
	}

	// Overwriting one tuple removes its pair as well.
	if err := ft.NewFlowFromTunDevice(
		fwdData,
		FlowData{
			Tuple: flowtrack.MakeTuple(
				ipproto.UDP,
				netip.MustParseAddrPort("9.9.9.9:99"),
				netip.MustParseAddrPort("8.8.8.8:88"),
			),
			Action: func(_ *packet.Parsed) {},
		},
	); err != nil {
		t.Fatalf("got non-nil error for new flow from tun device")
	}
	if _, err := ft.LookupFromWireGuard(revTuple); !errors.Is(err, ErrFlowNotFound) {
		t.Errorf("expected ErrFlowNotFound for removed reverse tuple")
	}

	// Nil action returns an error.
	if err := ft.NewFlowFromTunDevice(
		FlowData{},
		FlowData{},
	); err == nil {
		t.Errorf("expected non-nil error for nil data")
	}
}

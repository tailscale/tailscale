// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug && !ts_omit_connreject

package wgengine

import (
	"net/netip"
	"testing"

	"tailscale.com/net/connreject"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

// TestInboundTSMPRecordsRejection asserts that a parsed inbound TSMP reject
// packet is delivered as an outgoing-direction [connreject.Event] to the
// installed callback when trackOpenPreFilterIn processes it.
func TestInboundTSMPRecordsRejection(t *testing.T) {
	t.Parallel()
	var events []connreject.Event
	e := &userspaceEngine{}
	e.SetConnRejectCallback(func(evt connreject.Event) { events = append(events, evt) })

	rh := packet.TailscaleRejectedHeader{
		IPSrc:  netip.MustParseAddr("100.0.0.2"),
		IPDst:  netip.MustParseAddr("100.0.0.1"),
		Src:    netip.MustParseAddrPort("100.0.0.1:12345"),
		Dst:    netip.MustParseAddrPort("100.0.0.2:443"),
		Proto:  ipproto.TCP,
		Reason: packet.RejectedDueToACLs,
	}
	raw := packet.Generate(rh, nil)
	var pp packet.Parsed
	pp.Decode(raw)

	_ = e.trackOpenPreFilterIn(&pp, nil)

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	got := events[0]
	if got.Direction != connreject.Outgoing {
		t.Errorf("Direction = %v, want Outgoing", got.Direction)
	}
	if got.Source != connreject.SourceTSMPRecv {
		t.Errorf("Source = %v, want tsmp_recv", got.Source)
	}
	if got.Reason != connreject.ReasonACL {
		t.Errorf("Reason = %q, want %q", got.Reason, connreject.ReasonACL)
	}
	if got.Proto != ipproto.TCP {
		t.Errorf("Proto = %v, want TCP", got.Proto)
	}
	if got.Dst.Addr() != netip.MustParseAddr("100.0.0.2") {
		t.Errorf("Dst.Addr = %v, want 100.0.0.2", got.Dst.Addr())
	}
}

// TestInboundTSMPNonTerminalRecordsMaybeBroken asserts that a MaybeBroken
// TSMP reject is published with MaybeBroken=true.
func TestInboundTSMPNonTerminalRecordsMaybeBroken(t *testing.T) {
	t.Parallel()
	var events []connreject.Event
	e := &userspaceEngine{}
	e.SetConnRejectCallback(func(evt connreject.Event) { events = append(events, evt) })

	rh := packet.TailscaleRejectedHeader{
		IPSrc:       netip.MustParseAddr("100.0.0.2"),
		IPDst:       netip.MustParseAddr("100.0.0.1"),
		Src:         netip.MustParseAddrPort("100.0.0.1:12345"),
		Dst:         netip.MustParseAddrPort("100.0.0.2:443"),
		Proto:       ipproto.TCP,
		Reason:      packet.RejectedDueToHostFirewall,
		MaybeBroken: true,
	}
	raw := packet.Generate(rh, nil)
	var pp packet.Parsed
	pp.Decode(raw)

	_ = e.trackOpenPreFilterIn(&pp, nil)

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	got := events[0]
	if !got.MaybeBroken {
		t.Error("MaybeBroken = false, want true")
	}
	if got.Reason != connreject.ReasonHostFirewall {
		t.Errorf("Reason = %q, want %q", got.Reason, connreject.ReasonHostFirewall)
	}
}

// TestSetConnRejectCallbackUninstall verifies that SetConnRejectCallback(nil)
// safely clears the previously installed callback and that
// notifyConnRejectTSMPRecv is a safe no-op afterward.
func TestSetConnRejectCallbackUninstall(t *testing.T) {
	t.Parallel()
	var events []connreject.Event
	e := &userspaceEngine{}
	e.SetConnRejectCallback(func(evt connreject.Event) { events = append(events, evt) })

	rh := packet.TailscaleRejectedHeader{
		IPSrc:  netip.MustParseAddr("100.0.0.2"),
		IPDst:  netip.MustParseAddr("100.0.0.1"),
		Src:    netip.MustParseAddrPort("100.0.0.1:12345"),
		Dst:    netip.MustParseAddrPort("100.0.0.2:443"),
		Proto:  ipproto.TCP,
		Reason: packet.RejectedDueToACLs,
	}
	raw := packet.Generate(rh, nil)
	var pp packet.Parsed
	pp.Decode(raw)

	// First emit while installed: should deliver.
	_ = e.trackOpenPreFilterIn(&pp, nil)
	if len(events) != 1 {
		t.Fatalf("after install: got %d events, want 1", len(events))
	}

	// Uninstall and emit again: must not panic and must not deliver.
	e.SetConnRejectCallback(nil)
	_ = e.trackOpenPreFilterIn(&pp, nil)
	if len(events) != 1 {
		t.Errorf("after uninstall: got %d events, want still 1", len(events))
	}

	// Reinstall and emit a third time: should deliver again.
	e.SetConnRejectCallback(func(evt connreject.Event) { events = append(events, evt) })
	_ = e.trackOpenPreFilterIn(&pp, nil)
	if len(events) != 2 {
		t.Errorf("after reinstall: got %d events, want 2", len(events))
	}
}

func TestClassifyOpenTimeout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		in         openTimeoutDiag
		wantReason connreject.Reason
		wantSource connreject.Source
	}{
		{
			name:       "only-zero-route-suppresses-recording",
			in:         openTimeoutDiag{onlyZeroRoute: true},
			wantReason: "",
			wantSource: connreject.SourceUnknown,
		},
		{
			name:       "only-zero-route-suppresses-even-with-problem",
			in:         openTimeoutDiag{onlyZeroRoute: true, problem: packet.RejectedDueToACLs},
			wantReason: "",
			wantSource: connreject.SourceUnknown,
		},
		{
			name:       "problem-supersedes-diagnosis",
			in:         openTimeoutDiag{problem: packet.RejectedDueToACLs, noPeer: true},
			wantReason: connreject.ReasonACL,
			wantSource: connreject.SourceTSMPRecv,
		},
		{
			name:       "problem-host-firewall",
			in:         openTimeoutDiag{problem: packet.RejectedDueToHostFirewall},
			wantReason: connreject.ReasonHostFirewall,
			wantSource: connreject.SourceTSMPRecv,
		},
		{
			name:       "noPeer",
			in:         openTimeoutDiag{noPeer: true},
			wantReason: connreject.ReasonNoPeer,
			wantSource: connreject.SourcePendOpenTimeout,
		},
		{
			name:       "peerUnreachable",
			in:         openTimeoutDiag{peerUnreachable: true},
			wantReason: connreject.ReasonPeerUnreachable,
			wantSource: connreject.SourcePendOpenTimeout,
		},
		{
			name:       "plain-timeout",
			in:         openTimeoutDiag{},
			wantReason: connreject.ReasonTimeout,
			wantSource: connreject.SourcePendOpenTimeout,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotReason, gotSource := classifyOpenTimeout(tc.in)
			if gotReason != tc.wantReason {
				t.Errorf("reason = %q, want %q", gotReason, tc.wantReason)
			}
			if gotSource != tc.wantSource {
				t.Errorf("source = %q, want %q", gotSource, tc.wantSource)
			}
		})
	}
}

func TestRejectReasonToReason(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   packet.TailscaleRejectReason
		want connreject.Reason
	}{
		{packet.RejectedDueToACLs, connreject.ReasonACL},
		{packet.RejectedDueToShieldsUp, connreject.ReasonShields},
		{packet.RejectedDueToIPForwarding, connreject.ReasonHostIPForwarding},
		{packet.RejectedDueToHostFirewall, connreject.ReasonHostFirewall},
		{packet.TailscaleRejectReasonNone, connreject.ReasonUnknown},
	}
	for _, tc := range tests {
		if got := rejectReasonToReason(tc.in); got != tc.want {
			t.Errorf("rejectReasonToReason(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package connreject

import (
	"net/netip"
	"testing"

	"tailscale.com/net/connreject"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
)

// newTestExtension returns a fresh extension backed by an isolated
// Aggregator (no SafeBackend wiring), suitable for per-test use in
// parallel.
func newTestExtension() *extension {
	return &extension{
		logf: logger.Discard,
		agg:  connreject.NewAggregator(8),
	}
}

func sampleOutgoingEvent() connreject.Event {
	return connreject.Event{
		Direction: connreject.Outgoing,
		Proto:     ipproto.TCP,
		Src:       netip.MustParseAddrPort("100.0.0.1:1001"),
		Dst:       netip.MustParseAddrPort("100.0.0.2:443"),
		Reason:    connreject.ReasonACL,
		Source:    connreject.SourceTSMPRecv,
	}
}

func sampleIncomingEvent() connreject.Event {
	return connreject.Event{
		Direction: connreject.Incoming,
		Proto:     ipproto.TCP,
		Src:       netip.MustParseAddrPort("100.0.0.2:5555"),
		Dst:       netip.MustParseAddrPort("100.0.0.1:22"),
		Reason:    connreject.ReasonACL,
		Source:    connreject.SourceTSMPSent,
	}
}

// TestOnEventDeliversToAggregator verifies that events reaching the
// extension's callback are forwarded to the aggregator, which then
// partitions by direction into its own buffers.
func TestOnEventDeliversToAggregator(t *testing.T) {
	t.Parallel()
	e := newTestExtension()
	e.agg.SetEnabled(true)

	e.note(sampleOutgoingEvent())
	e.note(sampleIncomingEvent())

	if got := len(e.agg.Outgoing()); got != 1 {
		t.Errorf("outgoing len = %d, want 1", got)
	}
	if got := len(e.agg.Incoming()); got != 1 {
		t.Errorf("incoming len = %d, want 1", got)
	}
}

func TestOnEventDroppedWhenDisabled(t *testing.T) {
	t.Parallel()
	e := newTestExtension()

	e.note(sampleOutgoingEvent())
	e.note(sampleIncomingEvent())

	if got := len(e.agg.Outgoing()); got != 0 {
		t.Errorf("outgoing len = %d, want 0 when disabled", got)
	}
	if got := len(e.agg.Incoming()); got != 0 {
		t.Errorf("incoming len = %d, want 0 when disabled", got)
	}
}

func TestExtensionOnSelfChange(t *testing.T) {
	t.Parallel()
	e := newTestExtension()

	// NodeView without the cap → stays off.
	noCap := (&tailcfg.Node{}).View()
	e.onSelfChange(noCap)
	if e.agg.Enabled() {
		t.Error("enabled = true after self-change with no cap, want false")
	}

	// NodeView with the cap → turns on.
	withCap := (&tailcfg.Node{
		CapMap: tailcfg.NodeCapMap{
			tailcfg.NodeAttrConnReject: nil,
		},
	}).View()
	e.onSelfChange(withCap)
	if !e.agg.Enabled() {
		t.Error("enabled = false after self-change with cap, want true")
	}

	// Flipping back off works.
	e.onSelfChange(noCap)
	if e.agg.Enabled() {
		t.Error("enabled = true after flip back, want false")
	}
}

func TestExtensionShutdownDisables(t *testing.T) {
	t.Parallel()
	e := newTestExtension()
	e.agg.SetEnabled(true)

	if err := e.Shutdown(); err != nil {
		t.Fatalf("Shutdown error: %v", err)
	}
	if e.agg.Enabled() {
		t.Error("enabled still true after Shutdown")
	}
}

// TestBuildResponse covers the JSON-payload shape served by both the
// LocalAPI and c2n handlers. The handlers themselves are pure routing
// boilerplate (method check, extension lookup, JSON marshal) and are
// not exercised here; verifying buildResponse plus the
// FindMatchingExtension contract on LocalBackend is sufficient.
func TestBuildResponse(t *testing.T) {
	t.Parallel()
	e := newTestExtension()
	e.agg.SetEnabled(true)
	e.note(sampleOutgoingEvent())
	e.note(sampleIncomingEvent())

	resp := buildResponse(e.agg)
	if !resp.Enabled {
		t.Error("Enabled = false, want true")
	}
	if got := len(resp.Outgoing); got != 1 {
		t.Errorf("len(Outgoing) = %d, want 1", got)
	}
	if got := len(resp.Incoming); got != 1 {
		t.Errorf("len(Incoming) = %d, want 1", got)
	}

	// Disabled aggregator yields empty slices and Enabled=false.
	e.agg.SetEnabled(false)
	resp = buildResponse(e.agg)
	if resp.Enabled {
		t.Error("Enabled = true after SetEnabled(false), want false")
	}
}

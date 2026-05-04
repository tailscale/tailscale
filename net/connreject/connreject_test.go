// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package connreject

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/types/ipproto"
)

func outEvent(src, dst string, reason Reason, t time.Time) Event {
	return Event{
		Last:      t,
		Direction: Outgoing,
		Proto:     ipproto.TCP,
		Src:       netip.MustParseAddrPort(src),
		Dst:       netip.MustParseAddrPort(dst),
		Reason:    reason,
		Source:    SourceTSMPRecv,
	}
}

func inEvent(src, dst string, reason Reason, t time.Time) Event {
	return Event{
		Last:      t,
		Direction: Incoming,
		Proto:     ipproto.TCP,
		Src:       netip.MustParseAddrPort(src),
		Dst:       netip.MustParseAddrPort(dst),
		Reason:    reason,
		Source:    SourceTSMPSent,
	}
}

// newEnabled returns an Aggregator with the given max, with
// SetEnabled(true) already called.
func newEnabled(max int) *Aggregator {
	a := NewAggregator(max)
	a.SetEnabled(true)
	return a
}

func TestAggregatorDisabledByDefault(t *testing.T) {
	t.Parallel()
	a := NewAggregator(8)
	if a.Enabled() {
		t.Error("new Aggregator is enabled; want disabled by default")
	}
	a.Note(outEvent("100.0.0.1:1", "100.0.0.2:2", ReasonACL, time.Now()))
	a.Note(inEvent("100.0.0.2:2", "100.0.0.1:1", ReasonACL, time.Now()))
	if got := len(a.Outgoing()); got != 0 {
		t.Errorf("outgoing len = %d, want 0", got)
	}
	if got := len(a.Incoming()); got != 0 {
		t.Errorf("incoming len = %d, want 0", got)
	}
}

func TestAggregatorRejectsUnknownDirection(t *testing.T) {
	t.Parallel()
	a := newEnabled(8)
	// Event with no Direction set: silently dropped.
	a.Note(Event{
		Last:   time.Now(),
		Proto:  ipproto.TCP,
		Src:    netip.MustParseAddrPort("100.0.0.1:1"),
		Dst:    netip.MustParseAddrPort("100.0.0.2:2"),
		Reason: ReasonACL,
	})
	if got := len(a.Outgoing()) + len(a.Incoming()); got != 0 {
		t.Errorf("aggregator recorded event with unknown direction: %d entries", got)
	}
}

func TestAggregatorAggregatesByKey(t *testing.T) {
	t.Parallel()
	a := newEnabled(8)
	now := time.Now()
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonACL, now))
	a.Note(outEvent("100.0.0.1:1002", "100.0.0.2:443", ReasonACL, now.Add(1*time.Second)))
	a.Note(outEvent("100.0.0.1:1003", "100.0.0.2:443", ReasonACL, now.Add(2*time.Second)))

	all := a.Outgoing()
	if len(all) != 1 {
		t.Fatalf("got %d entries, want 1 (aggregated)", len(all))
	}
	e := all[0]
	if e.Count != 3 {
		t.Errorf("Count = %d, want 3", e.Count)
	}
	if !e.First.Equal(now) {
		t.Errorf("First = %v, want %v", e.First, now)
	}
	if !e.Last.Equal(now.Add(2 * time.Second)) {
		t.Errorf("Last = %v, want %v", e.Last, now.Add(2*time.Second))
	}
	if got, want := e.Src, netip.MustParseAddrPort("100.0.0.1:1003"); got != want {
		t.Errorf("Src = %v, want %v", got, want)
	}
}

func TestAggregatorDistinctByReason(t *testing.T) {
	t.Parallel()
	a := newEnabled(8)
	now := time.Now()
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonACL, now))
	a.Note(outEvent("100.0.0.1:1002", "100.0.0.2:443", ReasonShields, now.Add(1*time.Second)))

	if got := len(a.Outgoing()); got != 2 {
		t.Errorf("outgoing len = %d, want 2 (distinct reasons)", got)
	}
}

func TestAggregatorDistinctByProto(t *testing.T) {
	t.Parallel()
	a := newEnabled(8)
	now := time.Now()
	e1 := outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonACL, now)
	e2 := outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonACL, now.Add(time.Second))
	e2.Proto = ipproto.UDP

	a.Note(e1)
	a.Note(e2)

	if got := len(a.Outgoing()); got != 2 {
		t.Errorf("outgoing len = %d, want 2 (distinct protos)", got)
	}
}

func TestAggregatorDistinctByPeerAddr(t *testing.T) {
	t.Parallel()
	a := newEnabled(8)
	now := time.Now()
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonACL, now))
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.3:443", ReasonACL, now.Add(time.Second)))

	if got := len(a.Outgoing()); got != 2 {
		t.Errorf("outgoing len = %d, want 2 (distinct destinations)", got)
	}
}

func TestAggregatorPortNotInKey(t *testing.T) {
	t.Parallel()
	// For Outgoing, the peer address is Dst.Addr, so Dst port
	// differences should aggregate into one entry.
	a := newEnabled(8)
	now := time.Now()
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonACL, now))
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.2:8443", ReasonACL, now.Add(time.Second)))

	if got := len(a.Outgoing()); got != 1 {
		t.Errorf("outgoing len = %d, want 1 (dst port is not part of key)", got)
	}
}

func TestAggregatorIncomingKeyedBySrcAddr(t *testing.T) {
	t.Parallel()
	a := newEnabled(8)
	now := time.Now()
	// Same peer (100.0.0.2), different dst ports on us: should aggregate.
	a.Note(inEvent("100.0.0.2:5555", "100.0.0.1:22", ReasonACL, now))
	a.Note(inEvent("100.0.0.2:5556", "100.0.0.1:443", ReasonACL, now.Add(time.Second)))
	if got := len(a.Incoming()); got != 1 {
		t.Errorf("incoming len = %d, want 1 (src addr is the peer; dst port ignored)", got)
	}

	// Different peer: a second entry.
	a.Note(inEvent("100.0.0.3:5555", "100.0.0.1:22", ReasonACL, now.Add(2*time.Second)))
	if got := len(a.Incoming()); got != 2 {
		t.Errorf("incoming len = %d, want 2 (distinct source peers)", got)
	}
}

func TestAggregatorOutgoingAndIncomingIndependent(t *testing.T) {
	t.Parallel()
	// A single Aggregator's buffers are independent: a hit in one
	// direction does not aggregate with the other.
	a := newEnabled(8)
	now := time.Now()
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonACL, now))
	a.Note(inEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonACL, now))

	if got := len(a.Outgoing()); got != 1 {
		t.Errorf("outgoing len = %d, want 1", got)
	}
	if got := len(a.Incoming()); got != 1 {
		t.Errorf("incoming len = %d, want 1", got)
	}
}

func TestAggregatorLRUEviction(t *testing.T) {
	t.Parallel()
	a := newEnabled(2)
	now := time.Now()

	// Three distinct reasons → three distinct keys; cap is 2.
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonACL, now))
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonShields, now.Add(1*time.Second)))
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonHostFirewall, now.Add(2*time.Second)))

	all := a.Outgoing()
	if len(all) != 2 {
		t.Fatalf("len = %d, want 2", len(all))
	}
	// Oldest (ReasonACL) should have been evicted.
	want := []Reason{ReasonShields, ReasonHostFirewall}
	for i := range all {
		if all[i].Reason != want[i] {
			t.Errorf("entry[%d].Reason = %q, want %q", i, all[i].Reason, want[i])
		}
	}
}

func TestAggregatorLRUMovesOnHit(t *testing.T) {
	t.Parallel()
	a := newEnabled(2)
	now := time.Now()
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonACL, now))
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonShields, now.Add(1*time.Second)))
	// Hit the oldest entry; it should move to the back.
	a.Note(outEvent("100.0.0.1:1002", "100.0.0.2:443", ReasonACL, now.Add(2*time.Second)))
	// Now add a new one; ReasonShields should be evicted, not ReasonACL.
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonHostFirewall, now.Add(3*time.Second)))

	all := a.Outgoing()
	if len(all) != 2 {
		t.Fatalf("len = %d, want 2", len(all))
	}
	want := []Reason{ReasonACL, ReasonHostFirewall}
	for i := range all {
		if all[i].Reason != want[i] {
			t.Errorf("entry[%d].Reason = %q, want %q", i, all[i].Reason, want[i])
		}
	}
}

func TestAggregatorZeroMaxDisables(t *testing.T) {
	t.Parallel()
	a := newEnabled(0)
	a.Note(outEvent("100.0.0.1:1001", "100.0.0.2:443", ReasonACL, time.Now()))
	if got := len(a.Outgoing()); got != 0 {
		t.Errorf("outgoing = %d, want 0 (max<=0 disables)", got)
	}
}

func TestEventAutoTimestamps(t *testing.T) {
	t.Parallel()
	a := newEnabled(8)
	e := Event{
		Direction: Outgoing,
		Proto:     ipproto.TCP,
		Src:       netip.MustParseAddrPort("100.0.0.1:1001"),
		Dst:       netip.MustParseAddrPort("100.0.0.2:443"),
		Reason:    ReasonACL,
	}
	before := time.Now()
	a.Note(e)
	after := time.Now()

	all := a.Outgoing()
	if len(all) != 1 {
		t.Fatalf("len = %d, want 1", len(all))
	}
	got := all[0]
	if got.First.Before(before) || got.First.After(after) {
		t.Errorf("First = %v, not in [%v, %v]", got.First, before, after)
	}
	if got.Last.Before(got.First) {
		t.Errorf("Last %v before First %v", got.Last, got.First)
	}
	if got.Count != 1 {
		t.Errorf("Count = %d, want 1", got.Count)
	}
}

func TestEventJSONRoundTrip(t *testing.T) {
	t.Parallel()
	// Because Direction/Source/Reason are typed strings, encoding/json
	// handles them natively with no MarshalText boilerplate.
	want := Event{
		First:     time.Unix(1700000000, 0).UTC(),
		Last:      time.Unix(1700000060, 0).UTC(),
		Count:     3,
		Direction: Outgoing,
		Proto:     ipproto.TCP,
		Src:       netip.MustParseAddrPort("100.0.0.1:1001"),
		Dst:       netip.MustParseAddrPort("100.0.0.2:443"),
		Reason:    ReasonACL,
		Source:    SourceTSMPRecv,
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, fragment := range []string{
		`"Direction":"outgoing"`,
		`"Source":"tsmp_recv"`,
		`"Reason":"acl"`,
		`"Count":3`,
	} {
		if !strings.Contains(s, fragment) {
			t.Errorf("JSON missing %q; got %s", fragment, s)
		}
	}
	var got Event
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Direction != want.Direction ||
		got.Source != want.Source ||
		got.Reason != want.Reason ||
		got.Count != want.Count ||
		got.Src != want.Src ||
		got.Dst != want.Dst {
		t.Errorf("roundtrip mismatch\n got=%+v\nwant=%+v", got, want)
	}
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package pathpolicy

import (
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

func makeNode(tags ...string) tailcfg.NodeView {
	n := &tailcfg.Node{
		Tags: tags,
	}
	return n.View()
}

func makeNM(peers ...*tailcfg.Node) *netmap.NetworkMap {
	views := make([]tailcfg.NodeView, len(peers))
	for i, p := range peers {
		views[i] = p.View()
	}
	return &netmap.NetworkMap{Peers: views}
}

func TestPathEntriesFor_noPolicy(t *testing.T) {
	var e Engine
	got := e.PathEntriesFor(makeNode("tag:a"), makeNode("tag:b"))
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestPathEntriesFor_matchFirstRule(t *testing.T) {
	uplink := []tailcfg.PathEntry{
		{Type: tailcfg.PathEntryDirect, AF: tailcfg.PathEntryAFIPv6},
		{Type: tailcfg.PathEntryDERP},
	}
	nm := &netmap.NetworkMap{
		PathPolicy: &tailcfg.PathPolicy{
			Rules: []tailcfg.PathRule{
				{Src: []string{"tag:bj"}, Dst: []string{"tag:bj"}, Uplink: uplink},
				{Src: []string{"tag:other"}, Dst: []string{"tag:other"}, Uplink: []tailcfg.PathEntry{{Type: tailcfg.PathEntryDERP}}},
			},
		},
	}
	var e Engine
	e.Update(nm)

	got := e.PathEntriesFor(makeNode("tag:bj"), makeNode("tag:bj"))
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	if got[0].Type != tailcfg.PathEntryDirect {
		t.Errorf("want direct first, got %v", got[0].Type)
	}
}

func TestPathEntriesFor_noMatch(t *testing.T) {
	nm := &netmap.NetworkMap{
		PathPolicy: &tailcfg.PathPolicy{
			Rules: []tailcfg.PathRule{
				{Src: []string{"tag:bj"}, Dst: []string{"tag:bj"}, Uplink: []tailcfg.PathEntry{{Type: tailcfg.PathEntryDERP}}},
			},
		},
	}
	var e Engine
	e.Update(nm)
	got := e.PathEntriesFor(makeNode("tag:us"), makeNode("tag:us"))
	if got != nil {
		t.Fatalf("want nil for unmatched pair, got %v", got)
	}
}

func TestPathEntriesFor_downlinkDefault(t *testing.T) {
	// Rule with Uplink only (no Downlink). When self matches Dst and peer
	// matches Src, the engine should return nil (default best-route).
	uplink := []tailcfg.PathEntry{
		{Type: tailcfg.PathEntryRelay, Via: "tag:relay"},
		{Type: tailcfg.PathEntryDirect, AF: tailcfg.PathEntryAFIPv4},
	}
	nm := &netmap.NetworkMap{
		PathPolicy: &tailcfg.PathPolicy{
			Rules: []tailcfg.PathRule{
				{Src: []string{"tag:src"}, Dst: []string{"tag:dst"}, Uplink: uplink},
			},
		},
	}
	var e Engine
	e.Update(nm)

	// Forward direction: self=src, peer=dst → Uplink
	got := e.PathEntriesFor(makeNode("tag:src"), makeNode("tag:dst"))
	if len(got) != 2 {
		t.Fatalf("uplink: want 2 entries, got %d", len(got))
	}

	// Reverse direction: self=dst, peer=src → nil (default)
	got = e.PathEntriesFor(makeNode("tag:dst"), makeNode("tag:src"))
	if got != nil {
		t.Fatalf("downlink: want nil (default), got %v", got)
	}
}

func TestPathEntriesFor_explicitDownlink(t *testing.T) {
	uplink := []tailcfg.PathEntry{
		{Type: tailcfg.PathEntryRelay, Via: "tag:relay"},
	}
	downlink := []tailcfg.PathEntry{
		{Type: tailcfg.PathEntryDirect, AF: tailcfg.PathEntryAFIPv4},
	}
	nm := &netmap.NetworkMap{
		PathPolicy: &tailcfg.PathPolicy{
			Rules: []tailcfg.PathRule{
				{Src: []string{"tag:src"}, Dst: []string{"tag:dst"}, Uplink: uplink, Downlink: downlink},
			},
		},
	}
	var e Engine
	e.Update(nm)

	// Reverse direction: self=dst, peer=src → Downlink
	got := e.PathEntriesFor(makeNode("tag:dst"), makeNode("tag:src"))
	if len(got) != 1 || got[0].Type != tailcfg.PathEntryDirect {
		t.Fatalf("downlink: want [direct ipv4], got %v", got)
	}
}

func TestPathEntriesFor_symmetricPath(t *testing.T) {
	// Path applies to both directions symmetrically.
	entries := []tailcfg.PathEntry{
		{Type: tailcfg.PathEntryRelay, Via: "tag:relay"},
		{Type: tailcfg.PathEntryDirect},
	}
	nm := &netmap.NetworkMap{
		PathPolicy: &tailcfg.PathPolicy{
			Rules: []tailcfg.PathRule{
				{Src: []string{"tag:src"}, Dst: []string{"tag:dst"}, Path: entries},
			},
		},
	}
	var e Engine
	e.Update(nm)

	// Forward: self=src, peer=dst → Path
	got := e.PathEntriesFor(makeNode("tag:src"), makeNode("tag:dst"))
	if len(got) != 2 {
		t.Fatalf("forward: want 2 entries, got %d", len(got))
	}

	// Reverse: self=dst, peer=src → also Path (symmetric)
	got = e.PathEntriesFor(makeNode("tag:dst"), makeNode("tag:src"))
	if len(got) != 2 {
		t.Fatalf("reverse: want 2 entries, got %d", len(got))
	}
}

func TestPathEntriesFor_uplinkOverridesPath(t *testing.T) {
	// Uplink takes precedence over Path for the forward direction.
	pathEntries := []tailcfg.PathEntry{
		{Type: tailcfg.PathEntryDirect},
	}
	uplinkEntries := []tailcfg.PathEntry{
		{Type: tailcfg.PathEntryRelay, Via: "tag:relay"},
	}
	nm := &netmap.NetworkMap{
		PathPolicy: &tailcfg.PathPolicy{
			Rules: []tailcfg.PathRule{
				{Src: []string{"tag:src"}, Dst: []string{"tag:dst"}, Path: pathEntries, Uplink: uplinkEntries},
			},
		},
	}
	var e Engine
	e.Update(nm)

	// Forward: Uplink wins over Path
	got := e.PathEntriesFor(makeNode("tag:src"), makeNode("tag:dst"))
	if len(got) != 1 || got[0].Type != tailcfg.PathEntryRelay {
		t.Fatalf("forward: want [relay], got %v", got)
	}

	// Reverse: no Downlink, falls back to Path
	got = e.PathEntriesFor(makeNode("tag:dst"), makeNode("tag:src"))
	if len(got) != 1 || got[0].Type != tailcfg.PathEntryDirect {
		t.Fatalf("reverse: want [direct] from Path fallback, got %v", got)
	}
}

func TestAFAllowed(t *testing.T) {
	v4 := netip.MustParseAddr("1.2.3.4")
	v6 := netip.MustParseAddr("2001:db8::1")

	tests := []struct {
		af   tailcfg.PathEntryAF
		addr netip.Addr
		want bool
	}{
		{"", v4, true},
		{"", v6, true},
		{tailcfg.PathEntryAFIPv4, v4, true},
		{tailcfg.PathEntryAFIPv4, v6, false},
		{tailcfg.PathEntryAFIPv6, v4, false},
		{tailcfg.PathEntryAFIPv6, v6, true},
	}
	for _, tt := range tests {
		got := AFAllowed(tt.af, tt.addr)
		if got != tt.want {
			t.Errorf("AFAllowed(%q, %v) = %v, want %v", tt.af, tt.addr, got, tt.want)
		}
	}
}

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
	entries := []tailcfg.PathEntry{
		{Type: tailcfg.PathEntryDirect, AF: tailcfg.PathEntryAFIPv6},
		{Type: tailcfg.PathEntryDERP},
	}
	nm := &netmap.NetworkMap{
		PathPolicy: &tailcfg.PathPolicy{
			Rules: []tailcfg.PathRule{
				{Src: []string{"tag:bj"}, Dst: []string{"tag:bj"}, Path: entries},
				{Src: []string{"tag:other"}, Dst: []string{"tag:other"}, Path: []tailcfg.PathEntry{{Type: tailcfg.PathEntryDERP}}},
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
				{Src: []string{"tag:bj"}, Dst: []string{"tag:bj"}, Path: []tailcfg.PathEntry{{Type: tailcfg.PathEntryDERP}}},
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

func TestCandidateRelayChains(t *testing.T) {
	relay1 := &tailcfg.Node{ID: 1, Tags: []string{"tag:bj-relays"}}
	relay2 := &tailcfg.Node{ID: 2, Tags: []string{"tag:us-relays"}}
	nm := makeNM(relay1, relay2)
	nm.PathPolicy = &tailcfg.PathPolicy{
		Rules: []tailcfg.PathRule{
			{
				Src: []string{"tag:bj"},
				Dst: []string{"tag:bj"},
				Path: []tailcfg.PathEntry{
					{Type: tailcfg.PathEntryDirect},
					{Type: tailcfg.PathEntryRelay, Hops: []string{"tag:bj-relays"}},
					{Type: tailcfg.PathEntryRelay, Hops: []string{"tag:bj-relays", "tag:us-relays"}},
				},
			},
		},
	}
	var e Engine
	e.Update(nm)

	chains := e.CandidateRelayChains(makeNode("tag:bj"), makeNode("tag:bj"))
	if len(chains) != 2 {
		t.Fatalf("want 2 relay chains (single-hop + two-hop), got %d", len(chains))
	}
	if len(chains[0]) != 1 || len(chains[0][0]) != 1 {
		t.Errorf("chain[0] should be single-hop with 1 relay node")
	}
	if len(chains[1]) != 2 {
		t.Errorf("chain[1] should be two-hop")
	}
}

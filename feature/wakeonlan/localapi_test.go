// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wakeonlan

import (
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
)

// fakeNodeBackend implements the parts of [ipnext.NodeBackend] used by
// the LocalAPI handler.
type fakeNodeBackend struct {
	ipnext.NodeBackend
	self  tailcfg.NodeView
	peers []tailcfg.NodeView
}

func (f *fakeNodeBackend) Self() tailcfg.NodeView { return f.self }

func (f *fakeNodeBackend) all() []tailcfg.NodeView {
	return append([]tailcfg.NodeView{f.self}, f.peers...)
}

func (f *fakeNodeBackend) NodeByAddr(ip netip.Addr) (tailcfg.NodeID, bool) {
	for _, n := range f.all() {
		for _, a := range n.Addresses().All() {
			if a.Addr() == ip {
				return n.ID(), true
			}
		}
	}
	return 0, false
}

func (f *fakeNodeBackend) NodeByID(id tailcfg.NodeID) (tailcfg.NodeView, bool) {
	for _, n := range f.all() {
		if n.ID() == id {
			return n, true
		}
	}
	return tailcfg.NodeView{}, false
}

func (f *fakeNodeBackend) AppendMatchingPeers(base []tailcfg.NodeView, pred func(tailcfg.NodeView) bool) []tailcfg.NodeView {
	for _, p := range f.peers {
		if pred(p) {
			base = append(base, p)
		}
	}
	return base
}

func newTestNodeBackend() *fakeNodeBackend {
	node := func(id tailcfg.NodeID, name, ip string, macs ...string) tailcfg.NodeView {
		return (&tailcfg.Node{
			ID:        id,
			Name:      name,
			Addresses: []netip.Prefix{netip.MustParsePrefix(ip + "/32")},
			Hostinfo:  (&tailcfg.Hostinfo{WoLMACs: macs}).View(),
		}).View()
	}
	return &fakeNodeBackend{
		self: node(1, "laptop.example.ts.net.", "100.64.0.1"),
		peers: []tailcfg.NodeView{
			node(2, "desktop.example.ts.net.", "100.64.0.2", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"),
			node(3, "nas.example.ts.net.", "100.64.0.3"),
		},
	}
}

func TestResolveTargetMACs(t *testing.T) {
	nb := newTestNodeBackend()
	tests := []struct {
		target  string
		want    []string
		wantErr bool
	}{
		{target: "AA-BB-CC-00-11-22", want: []string{"aa:bb:cc:00:11:22"}},
		{target: "desktop", want: []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}},
		{target: "DESKTOP.example.ts.net", want: []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}},
		{target: "100.64.0.2", want: []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}},
		{target: "nas", wantErr: true},     // no advertised MACs
		{target: "printer", wantErr: true}, // unknown device
		{target: "100.64.9.9", wantErr: true},
		{target: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			macs, err := resolveTargetMACs(nb, tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			var got []string
			for _, m := range macs {
				got = append(got, m.String())
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindNode(t *testing.T) {
	nb := newTestNodeBackend()
	for s, wantID := range map[string]tailcfg.NodeID{
		"laptop":              1,
		"nas":                 3,
		"nas.example.ts.net.": 3,
		"100.64.0.2":          2,
	} {
		n, ok := findNode(nb, s)
		if !ok || n.ID() != wantID {
			t.Errorf("findNode(%q) = %v, %v; want node %v", s, n.ID(), ok, wantID)
		}
	}
	if _, ok := findNode(nb, "missing"); ok {
		t.Error("findNode(missing) found a node")
	}
}

func TestUniq(t *testing.T) {
	got := uniq([]string{"eth0", "eth0", "eth1", "wlan0", "wlan0"})
	if want := []string{"eth0", "eth1", "wlan0"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

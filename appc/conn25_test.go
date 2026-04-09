// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/types/opt"
)

type testNodeBackend struct {
	ipnext.NodeBackend
	peers []tailcfg.NodeView
}

func (nb *testNodeBackend) AppendMatchingPeers(base []tailcfg.NodeView, pred func(tailcfg.NodeView) bool) []tailcfg.NodeView {
	for _, p := range nb.peers {
		if pred(p) {
			base = append(base, p)
		}
	}
	return base
}

func (nb *testNodeBackend) PeerHasPeerAPI(p tailcfg.NodeView) bool {
	return true
}

func TestPickConnector(t *testing.T) {
	exampleApp := appctype.Conn25Attr{
		Name:       "example",
		Connectors: []string{"tag:example"},
		Domains:    []string{"example.com"},
	}

	nvWithConnectorSet := func(id tailcfg.NodeID, isConnector bool, tags ...string) tailcfg.NodeView {
		return (&tailcfg.Node{
			ID:       id,
			Tags:     tags,
			Hostinfo: (&tailcfg.Hostinfo{AppConnector: opt.NewBool(isConnector)}).View(),
		}).View()
	}

	nv := func(id tailcfg.NodeID, tags ...string) tailcfg.NodeView {
		return nvWithConnectorSet(id, true, tags...)
	}

	for _, tt := range []struct {
		name       string
		candidates []tailcfg.NodeView
		app        appctype.Conn25Attr
		want       []tailcfg.NodeView
	}{
		{
			name:       "empty-everything",
			candidates: []tailcfg.NodeView{},
			app:        appctype.Conn25Attr{},
			want:       nil,
		},
		{
			name:       "empty-candidates",
			candidates: []tailcfg.NodeView{},
			app:        exampleApp,
			want:       nil,
		},
		{
			name:       "empty-app",
			candidates: []tailcfg.NodeView{nv(1, "tag:example")},
			app:        appctype.Conn25Attr{},
			want:       nil,
		},
		{
			name:       "one-matches",
			candidates: []tailcfg.NodeView{nv(1, "tag:example")},
			app:        exampleApp,
			want:       []tailcfg.NodeView{nv(1, "tag:example")},
		},
		{
			name: "invalid-candidate",
			candidates: []tailcfg.NodeView{
				{},
				nv(1, "tag:example"),
			},
			app: exampleApp,
			want: []tailcfg.NodeView{
				nv(1, "tag:example"),
			},
		},
		{
			name: "no-host-info",
			candidates: []tailcfg.NodeView{
				(&tailcfg.Node{
					ID:   1,
					Tags: []string{"tag:example"},
				}).View(),
				nv(2, "tag:example"),
			},
			app:  exampleApp,
			want: []tailcfg.NodeView{nv(2, "tag:example")},
		},
		{
			name:       "not-a-connector",
			candidates: []tailcfg.NodeView{nvWithConnectorSet(1, false, "tag:example.com"), nv(2, "tag:example")},
			app:        exampleApp,
			want:       []tailcfg.NodeView{nv(2, "tag:example")},
		},
		{
			name:       "without-matches",
			candidates: []tailcfg.NodeView{nv(1, "tag:woo"), nv(2, "tag:example")},
			app:        exampleApp,
			want:       []tailcfg.NodeView{nv(2, "tag:example")},
		},
		{
			name:       "multi-tags",
			candidates: []tailcfg.NodeView{nv(1, "tag:woo", "tag:hoo"), nv(2, "tag:woo", "tag:example")},
			app:        exampleApp,
			want:       []tailcfg.NodeView{nv(2, "tag:woo", "tag:example")},
		},
		{
			name:       "multi-matches",
			candidates: []tailcfg.NodeView{nv(1, "tag:woo", "tag:hoo"), nv(2, "tag:woo", "tag:example"), nv(3, "tag:example1", "tag:example")},
			app: appctype.Conn25Attr{
				Name:       "example2",
				Connectors: []string{"tag:example1", "tag:example"},
				Domains:    []string{"example.com"},
			},
			want: []tailcfg.NodeView{nv(2, "tag:woo", "tag:example"), nv(3, "tag:example1", "tag:example")},
		},
		{
			name: "bit-of-everything",
			candidates: []tailcfg.NodeView{
				nv(3, "tag:woo", "tag:hoo"),
				{},
				nv(2, "tag:woo", "tag:example"),
				nvWithConnectorSet(4, false, "tag:example"),
				nv(1, "tag:example1", "tag:example"),
				nv(7, "tag:example1", "tag:example"),
				nvWithConnectorSet(5, false),
				nv(6),
				nvWithConnectorSet(8, false, "tag:example"),
				nvWithConnectorSet(9, false),
				nvWithConnectorSet(10, false),
			},
			app: appctype.Conn25Attr{
				Name:       "example2",
				Connectors: []string{"tag:example1", "tag:example", "tag:example2"},
				Domains:    []string{"example.com"},
			},
			want: []tailcfg.NodeView{
				nv(1, "tag:example1", "tag:example"),
				nv(2, "tag:woo", "tag:example"),
				nv(7, "tag:example1", "tag:example"),
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := PickConnector(&testNodeBackend{peers: tt.candidates}, tt.app)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("PickConnectors (-want, +got):\n%s", diff)
			}
		})
	}
}

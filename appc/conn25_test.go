// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/types/opt"
)

func TestPickSplitDNSPeers(t *testing.T) {
	getBytesForAttr := func(name string, domains []string, tags []string) []byte {
		attr := appctype.AppConnectorAttr{
			Name:       name,
			Domains:    domains,
			Connectors: tags,
		}
		bs, err := json.Marshal(attr)
		if err != nil {
			t.Fatalf("test setup: %v", err)
		}
		return bs
	}
	appOneBytes := getBytesForAttr("app1", []string{"example.com"}, []string{"tag:one"})
	appTwoBytes := getBytesForAttr("app2", []string{"a.example.com"}, []string{"tag:two"})
	appThreeBytes := getBytesForAttr("app3", []string{"woo.b.example.com", "hoo.b.example.com"}, []string{"tag:three1", "tag:three2"})
	appFourBytes := getBytesForAttr("app4", []string{"woo.b.example.com", "c.example.com"}, []string{"tag:four1", "tag:four2"})

	makeNodeView := func(id tailcfg.NodeID, name string, tags []string) tailcfg.NodeView {
		return (&tailcfg.Node{
			ID:       id,
			Name:     name,
			Tags:     tags,
			Hostinfo: (&tailcfg.Hostinfo{AppConnector: opt.NewBool(true)}).View(),
		}).View()
	}
	nvp1 := makeNodeView(1, "p1", []string{"tag:one"})
	nvp2 := makeNodeView(2, "p2", []string{"tag:four1", "tag:four2"})
	nvp3 := makeNodeView(3, "p3", []string{"tag:two", "tag:three1"})
	nvp4 := makeNodeView(4, "p4", []string{"tag:two", "tag:three2", "tag:four2"})

	for _, tt := range []struct {
		name   string
		want   map[string][]tailcfg.NodeView
		peers  []tailcfg.NodeView
		config []tailcfg.RawMessage
	}{
		{
			name: "empty",
		},
		{
			name:   "bad-config", // bad config should return a nil map rather than error.
			config: []tailcfg.RawMessage{tailcfg.RawMessage(`hey`)},
		},
		{
			name:   "no-peers",
			config: []tailcfg.RawMessage{tailcfg.RawMessage(appOneBytes)},
		},
		{
			name:   "peers-that-are-not-connectors",
			config: []tailcfg.RawMessage{tailcfg.RawMessage(appOneBytes)},
			peers: []tailcfg.NodeView{
				(&tailcfg.Node{
					ID:   5,
					Name: "p5",
					Tags: []string{"tag:one"},
				}).View(),
				(&tailcfg.Node{
					ID:   6,
					Name: "p6",
					Tags: []string{"tag:one"},
				}).View(),
			},
		},
		{
			name:   "peers-that-dont-match-tags",
			config: []tailcfg.RawMessage{tailcfg.RawMessage(appOneBytes)},
			peers: []tailcfg.NodeView{
				makeNodeView(5, "p5", []string{"tag:seven"}),
				makeNodeView(6, "p6", nil),
			},
		},
		{
			name: "matching-tagged-connector-peers",
			config: []tailcfg.RawMessage{
				tailcfg.RawMessage(appOneBytes),
				tailcfg.RawMessage(appTwoBytes),
				tailcfg.RawMessage(appThreeBytes),
				tailcfg.RawMessage(appFourBytes),
			},
			peers: []tailcfg.NodeView{
				nvp1,
				nvp2,
				nvp3,
				nvp4,
				makeNodeView(5, "p5", nil),
			},
			want: map[string][]tailcfg.NodeView{
				// p5 has no matching tags and so doesn't appear
				"example.com":       {nvp1},
				"a.example.com":     {nvp3, nvp4},
				"woo.b.example.com": {nvp2, nvp3, nvp4},
				"hoo.b.example.com": {nvp3, nvp4},
				"c.example.com":     {nvp2, nvp4},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			selfNode := &tailcfg.Node{}
			if tt.config != nil {
				selfNode.CapMap = tailcfg.NodeCapMap{
					tailcfg.NodeCapability(AppConnectorsExperimentalAttrName): tt.config,
				}
			}
			selfView := selfNode.View()
			peers := map[tailcfg.NodeID]tailcfg.NodeView{}
			for _, p := range tt.peers {
				peers[p.ID()] = p
			}
			got := PickSplitDNSPeers(func(_ tailcfg.NodeCapability) bool {
				return true
			}, selfView, peers)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
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
			want:       []tailcfg.NodeView{},
		},
		{
			name:       "empty-candidates",
			candidates: []tailcfg.NodeView{},
			app:        exampleApp,
			want:       []tailcfg.NodeView{},
		},
		{
			name:       "empty-app",
			candidates: []tailcfg.NodeView{nv(1, "tag:example")},
			app:        appctype.Conn25Attr{},
			want:       []tailcfg.NodeView{},
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
			got := PickConnector(tt.candidates, tt.app)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Fatalf("PickConnectors (-want, +got):\n%s", diff)
			}
		})
	}
}

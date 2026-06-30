// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/opt"
)

func TestAppDNSRoutes(t *testing.T) {
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
	appFiveBytes := getBytesForAttr("app5", []string{"*.example.com", "example.com"}, []string{"tag:one"})
	appSixBytes := getBytesForAttr("app6", []string{"*.Example.com", "EXAMPLE.com", "EXAMPLE.COM"}, []string{"tag:one"})

	resolver := func(appName string) []*dnstype.Resolver {
		return []*dnstype.Resolver{{Addr: fmt.Sprintf("%s:%s", DNSAddrScheme, appName)}}
	}

	for _, tt := range []struct {
		name   string
		hasCap bool
		config []tailcfg.RawMessage
		want   map[string][]*dnstype.Resolver
	}{
		{
			name:   "no-capability", // hasCap false should return nil regardless of config.
			hasCap: false,
		},
		{
			name:   "no-apps", // hasCap true but no configured apps returns an empty map.
			hasCap: true,
			want:   map[string][]*dnstype.Resolver{},
		},
		{
			name:   "bad-config", // bad config should return nil rather than error.
			hasCap: true,
			config: []tailcfg.RawMessage{tailcfg.RawMessage(`hey`)},
		},
		{
			name:   "single-app",
			hasCap: true,
			config: []tailcfg.RawMessage{tailcfg.RawMessage(appOneBytes)},
			want: map[string][]*dnstype.Resolver{
				"example.com": resolver("app1"),
			},
		},
		{
			name:   "single-app-multi-domain",
			hasCap: true,
			config: []tailcfg.RawMessage{tailcfg.RawMessage(appThreeBytes)},
			want: map[string][]*dnstype.Resolver{
				"woo.b.example.com": resolver("app3"),
				"hoo.b.example.com": resolver("app3"),
			},
		},
		{
			name:   "multi-app-no-overlap",
			hasCap: true,
			config: []tailcfg.RawMessage{
				tailcfg.RawMessage(appOneBytes),
				tailcfg.RawMessage(appTwoBytes),
			},
			want: map[string][]*dnstype.Resolver{
				"example.com":   resolver("app1"),
				"a.example.com": resolver("app2"),
			},
		},
		{
			name:   "domain-collision-last-write-wins",
			hasCap: true,
			config: []tailcfg.RawMessage{
				tailcfg.RawMessage(appThreeBytes), // app3: woo.b.example.com, hoo.b.example.com
				tailcfg.RawMessage(appFourBytes),  // app4: woo.b.example.com, c.example.com
			},
			want: map[string][]*dnstype.Resolver{
				// app4 overwrites app3 for the shared domain
				"woo.b.example.com": resolver("app4"),
				"hoo.b.example.com": resolver("app3"),
				"c.example.com":     resolver("app4"),
			},
		},
		{
			name:   "wildcards-are-stripped-and-deduped",
			hasCap: true,
			config: []tailcfg.RawMessage{tailcfg.RawMessage(appFiveBytes)},
			want: map[string][]*dnstype.Resolver{
				// *.example.com and example.com should both normalize to example.com.
				"example.com": resolver("app5"),
			},
		},
		{
			name:   "domains-are-normalized-and-deduped",
			hasCap: true,
			config: []tailcfg.RawMessage{tailcfg.RawMessage(appSixBytes)},
			want: map[string][]*dnstype.Resolver{
				// *.Example.com, EXAMPLE.com, EXAMPLE.COM should all normalize to example.com.
				"example.com": resolver("app6"),
			},
		},
		{
			name:   "sub-domains-and-top-domains-do-not-collide",
			hasCap: true,
			config: []tailcfg.RawMessage{
				tailcfg.RawMessage(appTwoBytes),
				tailcfg.RawMessage(appFiveBytes),
			},
			want: map[string][]*dnstype.Resolver{
				// *.example.com normalizes to example.com; a.example.com remains distinct.
				"a.example.com": resolver("app2"),
				"example.com":   resolver("app5"),
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
			got := AppDNSRoutes(func(_ tailcfg.NodeCapability) bool {
				return tt.hasCap
			}, selfView)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("AppDNSRoutes (-want, +got):\n%s", diff)
			}
		})
	}
}

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

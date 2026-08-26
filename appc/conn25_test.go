// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/appctype"
	"tailscale.com/types/dnstype"
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
		return []*dnstype.Resolver{{Addr: fmt.Sprintf("%s:%s", DNSAddrScheme, appName), UseWithExitNode: true}}
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
					nodecap.Cap(AppConnectorsExperimentalAttrName): tt.config,
				}
			}
			selfView := selfNode.View()
			got := AppDNSRoutes(func(_ nodecap.Cap) bool {
				return tt.hasCap
			}, selfView)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("AppDNSRoutes (-want, +got):\n%s", diff)
			}
		})
	}
}

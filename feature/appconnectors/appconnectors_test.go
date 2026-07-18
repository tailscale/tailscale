// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appconnectors

import (
	"slices"
	"testing"

	"tailscale.com/tailcfg"
)

func TestAdvertisedDomains(t *testing.T) {
	const cap = appConnectorCapName
	mkNode := func(tags []string, capJSON string) tailcfg.NodeView {
		n := &tailcfg.Node{Tags: tags}
		if capJSON != "" {
			n.CapMap = tailcfg.NodeCapMap{
				tailcfg.NodeCapability(cap): {tailcfg.RawMessage(capJSON)},
			}
		}
		return n.View()
	}

	tests := []struct {
		name string
		node tailcfg.NodeView
		want []string
	}{
		{
			name: "invalid_node",
			node: tailcfg.NodeView{},
			want: nil,
		},
		{
			name: "no_cap",
			node: mkNode([]string{"tag:appc"}, ""),
			want: nil,
		},
		{
			name: "wildcard_connector_matches",
			node: mkNode(nil, `{"name":"x","connectors":["*"],"domains":["b.com","a.com"]}`),
			want: []string{"a.com", "b.com"},
		},
		{
			name: "tag_match",
			node: mkNode([]string{"tag:appc"}, `{"name":"x","connectors":["tag:appc"],"domains":["a.com"]}`),
			want: []string{"a.com"},
		},
		{
			name: "tag_mismatch",
			node: mkNode([]string{"tag:other"}, `{"name":"x","connectors":["tag:appc"],"domains":["a.com"]}`),
			want: nil,
		},
		{
			name: "dedup_and_sort",
			node: mkNode([]string{"tag:appc"}, `{"name":"x","connectors":["tag:appc"],"domains":["b.com","a.com","a.com"]}`),
			want: []string{"a.com", "b.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := advertisedDomains(tt.node)
			if !slices.Equal(got, tt.want) {
				t.Errorf("advertisedDomains = %v, want %v", got, tt.want)
			}
		})
	}
}

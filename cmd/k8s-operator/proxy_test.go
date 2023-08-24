// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/util/must"
)

func TestImpersonationHeaders(t *testing.T) {
	tests := []struct {
		name     string
		emailish string
		tags     []string
		capMap   tailcfg.PeerCapMap

		wantHeaders http.Header
	}{
		{
			name:     "user",
			emailish: "foo@example.com",
			wantHeaders: http.Header{
				"Impersonate-User": {"foo@example.com"},
			},
		},
		{
			name:     "tagged",
			emailish: "tagged-device",
			tags:     []string{"tag:foo", "tag:bar"},
			wantHeaders: http.Header{
				"Impersonate-User":  {"node.ts.net"},
				"Impersonate-Group": {"tag:foo", "tag:bar"},
			},
		},
		{
			name:     "user-with-cap",
			emailish: "foo@example.com",
			capMap: tailcfg.PeerCapMap{
				capabilityName: {
					[]byte(`{"impersonate":{"groups":["group1","group2"]}}`),
					[]byte(`{"impersonate":{"groups":["group1","group3"]}}`), // One group is duplicated.
					[]byte(`{"impersonate":{"groups":["group4"]}}`),
					[]byte(`{"impersonate":{"groups":["group2"]}}`), // duplicate

					// These should be ignored, but should parse correctly.
					[]byte(`{}`),
					[]byte(`{"impersonate":{}}`),
					[]byte(`{"impersonate":{"groups":[]}}`),
				},
			},
			wantHeaders: http.Header{
				"Impersonate-Group": {"group1", "group2", "group3", "group4"},
				"Impersonate-User":  {"foo@example.com"},
			},
		},
		{
			name:     "tagged-with-cap",
			emailish: "tagged-device",
			tags:     []string{"tag:foo", "tag:bar"},
			capMap: tailcfg.PeerCapMap{
				capabilityName: {
					[]byte(`{"impersonate":{"groups":["group1"]}}`),
				},
			},
			wantHeaders: http.Header{
				"Impersonate-Group": {"group1"},
				"Impersonate-User":  {"node.ts.net"},
			},
		},
		{
			name:     "bad-cap",
			emailish: "tagged-device",
			tags:     []string{"tag:foo", "tag:bar"},
			capMap: tailcfg.PeerCapMap{
				capabilityName: {
					[]byte(`[]`),
				},
			},
			wantHeaders: http.Header{},
		},
	}

	for _, tc := range tests {
		r := must.Get(http.NewRequest("GET", "https://op.ts.net/api/foo", nil))
		r = addWhoIsToRequest(r, &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				Name: "node.ts.net",
				Tags: tc.tags,
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName: tc.emailish,
			},
			CapMap: tc.capMap,
		})
		addImpersonationHeaders(r)

		if d := cmp.Diff(tc.wantHeaders, r.Header); d != "" {
			t.Errorf("unexpected header (-want +got):\n%s", d)
		}
	}
}

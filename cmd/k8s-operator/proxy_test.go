// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/util/must"
)

func TestImpersonationHeaders(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
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
					tailcfg.RawMessage(`{"impersonate":{"groups":["group1","group2"]}}`),
					tailcfg.RawMessage(`{"impersonate":{"groups":["group1","group3"]}}`), // One group is duplicated.
					tailcfg.RawMessage(`{"impersonate":{"groups":["group4"]}}`),
					tailcfg.RawMessage(`{"impersonate":{"groups":["group2"]}}`), // duplicate

					// These should be ignored, but should parse correctly.
					tailcfg.RawMessage(`{}`),
					tailcfg.RawMessage(`{"impersonate":{}}`),
					tailcfg.RawMessage(`{"impersonate":{"groups":[]}}`),
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
					tailcfg.RawMessage(`{"impersonate":{"groups":["group1"]}}`),
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
					tailcfg.RawMessage(`[]`),
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
		addImpersonationHeaders(r, zl.Sugar())

		if d := cmp.Diff(tc.wantHeaders, r.Header); d != "" {
			t.Errorf("unexpected header (-want +got):\n%s", d)
		}
	}
}

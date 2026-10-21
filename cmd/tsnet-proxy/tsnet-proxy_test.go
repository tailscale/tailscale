// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type fakeWhoIs struct {
	resp *apitype.WhoIsResponse
	err  error
}

func (f fakeWhoIs) WhoIs(context.Context, string) (*apitype.WhoIsResponse, error) {
	return f.resp, f.err
}

func TestAddTailscaleIdentityHeaders(t *testing.T) {
	user := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{Name: "laptop.tail-scale.ts.net."},
		UserProfile: &tailcfg.UserProfile{
			LoginName:     "someone@example.com",
			DisplayName:   "Some One",
			ProfilePicURL: "https://example.com/photo.jpg",
		},
	}
	tagged := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			Name: "server.tail-scale.ts.net.",
			Tags: []string{"tag:prod", "tag:web"},
		},
		UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"},
	}

	tests := []struct {
		name string
		who  fakeWhoIs
		want map[string]string
	}{
		{
			name: "user",
			who:  fakeWhoIs{resp: user},
			want: map[string]string{
				"Tailscale-User-Login":       "someone@example.com",
				"Tailscale-User-Name":        "Some One",
				"Tailscale-User-Profile-Pic": "https://example.com/photo.jpg",
				"Tailscale-Headers-Info":     "https://tailscale.com/s/serve-headers",
			},
		},
		{
			name: "tagged-node",
			who:  fakeWhoIs{resp: tagged},
			want: map[string]string{
				"Tailscale-Node-Name":    "server.tail-scale.ts.net",
				"Tailscale-Node-Tags":    "tag:prod,tag:web",
				"Tailscale-Headers-Info": "https://tailscale.com/s/serve-headers",
			},
		},
		{
			name: "whois-error",
			who:  fakeWhoIs{err: errors.New("nope")},
		},
		{
			name: "whois-nil",
			who:  fakeWhoIs{},
		},
		{
			name: "whois-nil-node",
			who:  fakeWhoIs{resp: &apitype.WhoIsResponse{}},
		},
		{
			name: "whois-nil-user-profile",
			who:  fakeWhoIs{resp: &apitype.WhoIsResponse{Node: user.Node}},
		},
	}
	allHeaders := []string{
		"Tailscale-User-Login",
		"Tailscale-User-Name",
		"Tailscale-User-Profile-Pic",
		"Tailscale-Node-Name",
		"Tailscale-Node-Tags",
		"Tailscale-Funnel-Request",
		"Tailscale-Headers-Info",
		"Tailscale-App-Capabilities",
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := httptest.NewRequest("GET", "http://example.com/", nil)
			in.RemoteAddr = "100.64.0.1:1234"
			// Spoofed values from the client must never reach the backend.
			for _, h := range allHeaders {
				in.Header.Set(h, "spoofed")
			}
			pr := &httputil.ProxyRequest{In: in, Out: in.Clone(in.Context())}

			addTailscaleIdentityHeaders(tt.who, pr)

			for _, h := range allHeaders {
				if got, want := pr.Out.Header.Get(h), tt.want[h]; got != want {
					t.Errorf("header %s = %q; want %q", h, got, want)
				}
			}
			if got := in.Header.Get("Tailscale-User-Login"); got != "spoofed" {
				t.Errorf("incoming request was mutated: Tailscale-User-Login = %q", got)
			}
		})
	}
}

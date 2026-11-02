// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package identityheaders

import (
	"net/http"
	"testing"

	"tailscale.com/tailcfg"
)

var allHeaders = []string{
	UserLogin, UserName, UserProfilePic, NodeName, NodeTags, FunnelRequest, HeadersInfo, AppCapabilities,
}

func TestStripAndSet(t *testing.T) {
	user := (&tailcfg.UserProfile{
		LoginName:     "someone@example.com",
		DisplayName:   "Søme One",
		ProfilePicURL: "https://example.com/photo.jpg",
	}).View()
	tests := []struct {
		name string
		node tailcfg.NodeView
		user tailcfg.UserProfileView
		want map[string]string
	}{
		{
			name: "user",
			node: (&tailcfg.Node{Name: "laptop.ts.net."}).View(),
			user: user,
			want: map[string]string{
				UserLogin:      "someone@example.com",
				UserName:       "=?utf-8?q?S=C3=B8me_One?=",
				UserProfilePic: "https://example.com/photo.jpg",
				HeadersInfo:    headersInfoURL,
			},
		},
		{
			name: "tagged",
			node: (&tailcfg.Node{
				Name: "server.ts.net.",
				Tags: []string{"tag:prod", "tag:web"},
			}).View(),
			user: (&tailcfg.UserProfile{LoginName: "tagged-devices"}).View(),
			want: map[string]string{
				NodeName:    "server.ts.net",
				NodeTags:    "tag:prod,tag:web",
				HeadersInfo: headersInfoURL,
			},
		},
		{
			name: "invalid-node",
		},
		{
			name: "user-node-invalid-user",
			node: (&tailcfg.Node{Name: "laptop.ts.net."}).View(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for _, k := range allHeaders {
				h.Set(k, "spoofed")
			}
			Strip(h)
			for _, k := range allHeaders {
				if v := h.Get(k); v != "" {
					t.Errorf("Strip left %s = %q", k, v)
				}
			}
			Set(h, tt.node, tt.user)
			for _, k := range allHeaders {
				if got, want := h.Get(k), tt.want[k]; got != want {
					t.Errorf("%s = %q; want %q", k, got, want)
				}
			}
		})
	}
}

func TestEncode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"Alice Smith", "Alice Smith"},
		{"Bad\xffUTF-8", ""},
		{"Krūmiņa", "=?utf-8?q?Kr=C5=ABmi=C5=86a?="},
	}
	for _, tt := range tests {
		if got := Encode(tt.in); got != tt.want {
			t.Errorf("Encode(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	"net/url"
	"testing"
)

func TestClientBuildURL(t *testing.T) {
	c := Client{BaseURL: "http://127.0.0.1:1234"}
	for _, tt := range []struct {
		desc     string
		elements []any
		want     string
	}{
		{
			desc:     "single-element",
			elements: []any{"devices"},
			want:     "http://127.0.0.1:1234/api/v2/devices",
		},
		{
			desc:     "multiple-elements",
			elements: []any{"tailnet", "example.com"},
			want:     "http://127.0.0.1:1234/api/v2/tailnet/example.com",
		},
		{
			desc:     "escape-element",
			elements: []any{"tailnet", "example dot com?foo=bar"},
			want:     `http://127.0.0.1:1234/api/v2/tailnet/example%20dot%20com%3Ffoo=bar`,
		},
		{
			desc:     "url.Values",
			elements: []any{"tailnet", "example.com", "acl", url.Values{"details": {"1"}}},
			want:     `http://127.0.0.1:1234/api/v2/tailnet/example.com/acl?details=1`,
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			got := c.BuildURL(tt.elements...)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientBuildTailnetURL(t *testing.T) {
	c := Client{
		BaseURL: "http://127.0.0.1:1234",
		tailnet: "example.com",
	}
	for _, tt := range []struct {
		desc     string
		elements []any
		want     string
	}{
		{
			desc:     "single-element",
			elements: []any{"devices"},
			want:     "http://127.0.0.1:1234/api/v2/tailnet/example.com/devices",
		},
		{
			desc:     "multiple-elements",
			elements: []any{"devices", 123},
			want:     "http://127.0.0.1:1234/api/v2/tailnet/example.com/devices/123",
		},
		{
			desc:     "escape-element",
			elements: []any{"foo bar?baz=qux"},
			want:     `http://127.0.0.1:1234/api/v2/tailnet/example.com/foo%20bar%3Fbaz=qux`,
		},
		{
			desc:     "url.Values",
			elements: []any{"acl", url.Values{"details": {"1"}}},
			want:     `http://127.0.0.1:1234/api/v2/tailnet/example.com/acl?details=1`,
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			got := c.BuildTailnetURL(tt.elements...)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

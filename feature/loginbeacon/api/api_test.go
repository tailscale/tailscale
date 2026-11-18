// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package api

import "testing"

func TestDefaultURLAllowed(t *testing.T) {
	cases := map[string]bool{
		"https://login.tailscale.com/x":  true,
		"https://foo.tailscale.com/y":    false,
		"http://login.tailscale.com/x":   false,
		"https://evil.example.com/x":     false,
		"https://tailscale.com.evil.com": false,
		"":                               false,
	}
	for u, want := range cases {
		if got := DefaultURLAllowed(u); got != want {
			t.Errorf("DefaultURLAllowed(%q) = %v; want %v", u, got, want)
		}
	}
}

func TestAuthenticationOriginPolicy(t *testing.T) {
	for _, raw := range []string{"https://user:pass@login.tailscale.com/a/x", "https://foo.tailscale.com/a/x", "https://login.tailscale.com:444/a/x", "http://login.tailscale.com/a/x", "https://login.tailscale.com.evil.example/a/x"} {
		if DefaultURLAllowed(raw) {
			t.Errorf("allowed %q", raw)
		}
	}
}

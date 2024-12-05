// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"testing"
)

func TestUrlOfListenAddr(t *testing.T) {
	tests := []struct {
		name     string
		in, want string
	}{
		{
			name: "TestLocalhost",
			in:   "localhost:8088",
			want: "http://localhost:8088",
		},
		{
			name: "TestNoHost",
			in:   ":8088",
			want: "http://127.0.0.1:8088",
		},
		{
			name: "TestExplicitHost",
			in:   "127.0.0.2:8088",
			want: "http://127.0.0.2:8088",
		},
		{
			name: "TestIPv6",
			in:   "[::1]:8088",
			want: "http://[::1]:8088",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := urlOfListenAddr(tt.in)
			if u != tt.want {
				t.Errorf("expected url: %q, got: %q", tt.want, u)
			}
		})
	}
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tswebutil

import (
	"net/http"
	"testing"
)

func TestAcceptsEncoding(t *testing.T) {
	tests := []struct {
		in, enc string
		want    bool
	}{
		{"", "gzip", false},
		{"gzip", "gzip", true},
		{"foo,gzip", "gzip", true},
		{"foo, gzip", "gzip", true},
		{"foo, gzip ", "gzip", true},
		{"gzip, foo ", "gzip", true},
		{"gzip, foo ", "br", false},
		{"gzip, foo ", "fo", false},
		{"gzip;q=1.2, foo ", "gzip", true},
		{" gzip;q=1.2, foo ", "gzip", true},
	}
	for i, tt := range tests {
		h := make(http.Header)
		if tt.in != "" {
			h.Set("Accept-Encoding", tt.in)
		}
		got := AcceptsEncoding(&http.Request{Header: h}, tt.enc)
		if got != tt.want {
			t.Errorf("%d. got %v; want %v", i, got, tt.want)
		}
	}
}

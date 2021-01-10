// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsname

import "testing"

func TestHasSuffix(t *testing.T) {
	tests := []struct {
		name, suffix string
		want         bool
	}{
		{"foo.com", "com", true},
		{"foo.com.", "com", true},
		{"foo.com.", "com.", true},

		{"", "", false},
		{"foo.com.", "", false},
		{"foo.com.", "o.com", false},
	}
	for _, tt := range tests {
		got := HasSuffix(tt.name, tt.suffix)
		if got != tt.want {
			t.Errorf("HasSuffix(%q, %q) = %v; want %v", tt.name, tt.suffix, got, tt.want)
		}
	}
}

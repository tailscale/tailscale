// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !ios && !android && !js
// +build !ios,!android,!js

package localapi

import "testing"

func TestValidLookingCertDomain(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"foo.com", true},
		{"foo..com", false},
		{"foo/com.com", false},
		{"NUL", false},
		{"", false},
		{"foo\\bar.com", false},
		{"foo\x00bar.com", false},
	}
	for _, tt := range tests {
		if got := validLookingCertDomain(tt.in); got != tt.want {
			t.Errorf("validLookingCertDomain(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

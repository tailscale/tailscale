// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tstest

import "testing"

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		release             string
		major, minor, patch int
	}{
		{"5.15.0-76-generic", 5, 15, 0},
		{"6.12.73+deb13-amd64", 6, 12, 73},
		{"6.1.0-18-amd64", 6, 1, 0},
		{"5.4.0", 5, 4, 0},
		{"6.8.12", 6, 8, 12},
		{"4.19.0+1", 4, 19, 0},
		{"6.12.41+deb13-amd64", 6, 12, 41},
		{"", 0, 0, 0},
		{"not-a-version", 0, 0, 0},
		{"1.2", 0, 0, 0},
		{"a.b.c", 0, 0, 0},
	}
	for _, tt := range tests {
		major, minor, patch := parseKernelVersion(tt.release)
		if major != tt.major || minor != tt.minor || patch != tt.patch {
			t.Errorf("parseKernelVersion(%q) = (%d, %d, %d), want (%d, %d, %d)",
				tt.release, major, minor, patch, tt.major, tt.minor, tt.patch)
		}
	}
}

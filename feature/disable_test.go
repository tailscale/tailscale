// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package feature

import "testing"

func TestNormalizeFeatureName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"taildrop", "taildrop"},
		{" taildrop ", "taildrop"},
		{"Taildrop", "taildrop"},
		{"TAILDROP", "taildrop"},
		{"ts_omit_taildrop", "taildrop"},
		{"TS_OMIT_TAILDROP", "taildrop"},
		{"desktop_sessions", "desktop-sessions"},
		{"ts_omit_desktop_sessions", "desktop-sessions"},
		{"", ""},
		{"  ", ""},
		{",", ","},
	}
	for _, tt := range tests {
		if got := normalizeFeatureName(tt.in); got != tt.want {
			t.Errorf("normalizeFeatureName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseDisabledList(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{",", nil},
		{" , ", nil},
		{"taildrop", []string{"taildrop"}},
		{"ssh,taildrop", []string{"ssh", "taildrop"}},
		{" ssh , taildrop ", []string{"ssh", "taildrop"}},
		{"ssh,,taildrop,", []string{"ssh", "taildrop"}},
		{"TS_OMIT_SSH,TailnetLock", []string{"ssh", "tailnetlock"}},
	}
	for _, tt := range tests {
		got := parseDisabledList(tt.in)
		if len(got) != len(tt.want) {
			t.Errorf("parseDisabledList(%q) = %q, want %q", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseDisabledList(%q) = %q, want %q", tt.in, got, tt.want)
				break
			}
		}
	}
}

// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsname

import (
	"strings"
	"testing"
)

func TestSanitizeLabel(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"space", " ", ""},
		{"upper", "OBERON", "oberon"},
		{"mixed", "Avery's iPhone 4(SE)", "averys-iphone-4se"},
		{"dotted", "mon.ipn.dev", "mon-ipn-dev"},
		{"email", "admin@example.com", "admin-example-com"},
		{"boudary", ".bound.ary.", "bound-ary"},
		{"bad_trailing", "a-", "a"},
		{"bad_leading", "-a", "a"},
		{"bad_both", "-a-", "a"},
		{
			"overlong",
			strings.Repeat("test.", 20),
			"test-test-test-test-test-test-test-test-test-test-test-test-tes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeLabel(tt.in)
			if got != tt.want {
				t.Errorf("want %q; got %q", tt.want, got)
			}
		})
	}
}

func TestTrimCommonSuffixes(t *testing.T) {
	tests := []struct {
		hostname string
		want     string
	}{
		{"computer.local", "computer"},
		{"computer.localdomain", "computer"},
		{"computer.lan", "computer"},
		{"computer.mynetwork", "computer.mynetwork"},
	}
	for _, tt := range tests {
		got := TrimCommonSuffixes(tt.hostname)
		if got != tt.want {
			t.Errorf("TrimCommonSuffixes(%q) = %q; want %q", tt.hostname, got, tt.want)
		}
	}
}

func TestHasSuffix(t *testing.T) {
	tests := []struct {
		name, suffix string
		want         bool
	}{
		{"foo.com", "com", true},
		{"foo.com.", "com", true},
		{"foo.com.", "com.", true},
		{"foo.com", ".com", true},

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

func TestTrimSuffix(t *testing.T) {
	tests := []struct {
		name   string
		suffix string
		want   string
	}{
		{"foo.magicdnssuffix.", "magicdnssuffix", "foo"},
		{"foo.magicdnssuffix", "magicdnssuffix", "foo"},
		{"foo.magicdnssuffix", ".magicdnssuffix", "foo"},
		{"foo.anothersuffix", "magicdnssuffix", "foo.anothersuffix"},
		{"foo.anothersuffix.", "magicdnssuffix", "foo.anothersuffix"},
		{"a.b.c.d", "c.d", "a.b"},
		{"name.", "foo", "name"},
	}
	for _, tt := range tests {
		got := TrimSuffix(tt.name, tt.suffix)
		if got != tt.want {
			t.Errorf("TrimSuffix(%q, %q) = %q; want %q", tt.name, tt.suffix, got, tt.want)
		}
	}
}

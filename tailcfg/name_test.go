// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tailcfg

import (
	"strings"
	"testing"
)

func TestSanitizeNameLabel(t *testing.T) {
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
			got := SanitizeNameLabel(tt.in)
			if got != tt.want {
				t.Errorf("want %s; got %s", tt.want, got)
			}
		})
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"single_label", "OBERON", "oberon"},
		{"dotted", "MON.IPN.DEV", "mon.ipn.dev"},
		{"email", "first.last@example.com", "first-last.example.com"},
		{"weird", "\"first..last(c+d)?\"@email.com", "first--lastcd.email.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeName(tt.in)
			if got != tt.want {
				t.Errorf("want %s; got %s", tt.want, got)
			}
		})
	}
}

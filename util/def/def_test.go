// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package def_test

import (
	"testing"
	"time"

	"tailscale.com/util/def"
)

func TestBool(t *testing.T) {
	tests := []struct {
		name string
		in   string
		def  bool
		want bool
	}{
		{name: "empty true", in: "", def: true, want: true},
		{name: "empty false", in: "", def: false, want: false},
		{name: "valid true", in: "true", def: false, want: true},
		{name: "valid false", in: "false", def: true, want: false},
		{name: "strconv shorthand", in: "1", def: false, want: true},
		{name: "invalid true", in: "sure", def: true, want: true},
		{name: "invalid false", in: "sure", def: false, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := def.Bool(tt.in, tt.def); got != tt.want {
				t.Errorf("Bool(%q, %v) = %v; want %v", tt.in, tt.def, got, tt.want)
			}
		})
	}
}

func TestDuration(t *testing.T) {
	tests := []struct {
		name string
		in   string
		def  time.Duration
		want time.Duration
	}{
		{name: "empty", in: "", def: time.Second, want: time.Second},
		{name: "valid", in: "2m30s", def: time.Second, want: 150 * time.Second},
		{name: "invalid", in: "soon", def: time.Second, want: time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := def.Duration(tt.in, tt.def); got != tt.want {
				t.Errorf("Duration(%q, %v) = %v; want %v", tt.in, tt.def, got, tt.want)
			}
		})
	}
}

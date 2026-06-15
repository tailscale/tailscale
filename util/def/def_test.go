// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package def_test

import (
	"strconv"
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
		{name: "empty_true", in: "", def: true, want: true},
		{name: "empty_false", in: "", def: false, want: false},
		{name: "valid_1", in: "1", def: false, want: true},
		{name: "valid_t", in: "t", def: false, want: true},
		{name: "valid_T", in: "T", def: false, want: true},
		{name: "valid_TRUE", in: "TRUE", def: false, want: true},
		{name: "valid_true", in: "true", def: false, want: true},
		{name: "valid_True", in: "True", def: false, want: true},
		{name: "valid_true_default_true", in: "true", def: true, want: true},
		{name: "valid_0", in: "0", def: true, want: false},
		{name: "valid_f", in: "f", def: true, want: false},
		{name: "valid_F", in: "F", def: true, want: false},
		{name: "valid_FALSE", in: "FALSE", def: true, want: false},
		{name: "valid_false", in: "false", def: true, want: false},
		{name: "valid_False", in: "False", def: true, want: false},
		{name: "valid_false_default_false", in: "false", def: false, want: false},
		{name: "invalid_true", in: "sure", def: true, want: true},
		{name: "invalid_false", in: "sure", def: false, want: false},
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
		{name: "empty_second", in: "", def: time.Second, want: time.Second},
		{name: "empty_zero", in: "", def: 0, want: 0},
		{name: "valid", in: "2m30s", def: time.Second, want: 2*time.Minute + 30*time.Second},
		{name: "valid_zero", in: "0s", def: time.Second, want: 0},
		{name: "invalid_second", in: "soon", def: time.Second, want: time.Second},
		{name: "invalid_minute", in: "soon", def: time.Minute, want: time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := def.Duration(tt.in, tt.def); got != tt.want {
				t.Errorf("Duration(%q, %v) = %v; want %v", tt.in, tt.def, got, tt.want)
			}
		})
	}
}

func FuzzBool(f *testing.F) {
	for _, tc := range []struct {
		in  string
		def bool
	}{
		{in: "", def: true},
		{in: "", def: false},
		{in: "true", def: false},
		{in: "false", def: true},
		{in: "sure", def: true},
		{in: "sure", def: false},
	} {
		f.Add(tc.in, tc.def)
	}
	f.Fuzz(func(t *testing.T, in string, fallback bool) {
		got := def.Bool(in, fallback)
		want, err := strconv.ParseBool(in)
		if in == "" || err != nil {
			want = fallback
		}
		if got != want {
			t.Fatalf("Bool(%q, %v) = %v; want %v", in, fallback, got, want)
		}
	})
}

func FuzzDuration(f *testing.F) {
	for _, tc := range []struct {
		in  string
		def time.Duration
	}{
		{in: "", def: time.Second},
		{in: "", def: 0},
		{in: "2m30s", def: time.Second},
		{in: "soon", def: time.Second},
	} {
		f.Add(tc.in, int64(tc.def))
	}
	f.Fuzz(func(t *testing.T, in string, fallbackN int64) {
		fallback := time.Duration(fallbackN)
		got := def.Duration(in, fallback)
		want, err := time.ParseDuration(in)
		if in == "" || err != nil {
			want = fallback
		}
		if got != want {
			t.Fatalf("Duration(%q, %v) = %v; want %v", in, fallback, got, want)
		}
	})
}

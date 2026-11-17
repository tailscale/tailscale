// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package def

import (
	"strconv"
	"testing"
	"time"
)

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
		got := Bool(in, fallback)
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
		got := Duration(in, fallback)
		want, err := time.ParseDuration(in)
		if in == "" || err != nil {
			want = fallback
		}
		if got != want {
			t.Fatalf("Duration(%q, %v) = %v; want %v", in, fallback, got, want)
		}
	})
}

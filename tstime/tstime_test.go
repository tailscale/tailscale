// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstime

import (
	"testing"
	"time"
)

func TestZoneOf(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"2020-04-05T15:56:00+08:00", "+08:00"},
		{"2020-04-05T15:56:00-08:00", "-08:00"},
		{"2020-04-05T15:56:00.12345-08:00", "-08:00"},
		// don't cache weird offsets, only 00 15, 30:
		{"2020-04-05T15:56:00.12345-08:00", "-08:00"},
		{"2020-04-05T15:56:00.12345-08:30", "-08:30"},
		{"2020-04-05T15:56:00.12345-08:15", "-08:15"},
		{"2020-04-05T15:56:00.12345-08:17", ""},
		// don't cache UTC:
		{"2020-04-05T15:56:00.12345Z", ""},
		{"2020-04-05T15:56:00Z", ""},
		// too short:
		{"123+08:00", ""},
		{"+08:00", ""},
	}
	for _, tt := range tests {
		if got := zoneOf(tt.in); got != tt.want {
			t.Errorf("zoneOf(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

func BenchmarkGoParse3339(b *testing.B) {
	b.ReportAllocs()
	const in = `2020-04-05T15:56:00.148487491+08:00`
	for i := 0; i < b.N; i++ {
		_, err := time.Parse(time.RFC3339Nano, in)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGoParse3339InLocation(b *testing.B) {
	b.ReportAllocs()
	const in = `2020-04-05T15:56:00.148487491+08:00`

	t, err := time.Parse(time.RFC3339Nano, in)
	if err != nil {
		b.Fatal(err)
	}
	loc := t.Location()

	t2, err := time.ParseInLocation(time.RFC3339Nano, in, loc)
	if err != nil {
		b.Fatal(err)
	}
	if !t.Equal(t2) {
		b.Fatal("not equal")
	}
	if s1, s2 := t.Format(time.RFC3339Nano), t2.Format(time.RFC3339Nano); s1 != s2 {
		b.Fatalf("times don't stringify the same: %q vs %q", s1, s2)
	}

	for i := 0; i < b.N; i++ {
		_, err := time.ParseInLocation(time.RFC3339Nano, in, loc)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParse3339(b *testing.B) {
	b.ReportAllocs()
	const in = `2020-04-05T15:56:00.148487491+08:00`

	t, err := time.Parse(time.RFC3339Nano, in)
	if err != nil {
		b.Fatal(err)
	}

	t2, err := Parse3339(in)
	if err != nil {
		b.Fatal(err)
	}
	if !t.Equal(t2) {
		b.Fatal("not equal")
	}
	if s1, s2 := t.Format(time.RFC3339Nano), t2.Format(time.RFC3339Nano); s1 != s2 {
		b.Fatalf("times don't stringify the same: %q vs %q", s1, s2)
	}

	for i := 0; i < b.N; i++ {
		_, err := Parse3339(in)
		if err != nil {
			b.Fatal(err)
		}
	}
}

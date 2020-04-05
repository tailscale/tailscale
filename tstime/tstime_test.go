// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstime

import (
	"testing"
	"time"
)

func TestZoneOf(t *testing.T) {
	if got, want := zoneOf("2020-04-05T15:56:00+08:00"), "+08:00"; got != want {
		t.Errorf("got %q; want %q", got, want)
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

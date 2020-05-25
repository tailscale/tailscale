// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package strbuilder

import (
	"math"
	"testing"
)

func TestBuilder(t *testing.T) {
	const want = "Hello, world 123 -456!"
	bang := []byte("!")
	var got string
	allocs := testing.AllocsPerRun(1000, func() {
		sb := Get()
		sb.WriteString("Hello, world ")
		sb.WriteUint(123)
		sb.WriteByte(' ')
		sb.WriteInt(-456)
		sb.Write(bang)
		got = sb.String()
	})
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
	if allocs != 1 {
		t.Errorf("allocs = %v; want 1", allocs)
	}
}

// Verifies scratch buf is large enough.
func TestIntBounds(t *testing.T) {
	const want = "-9223372036854775808 9223372036854775807 18446744073709551615"
	var got string
	allocs := testing.AllocsPerRun(1000, func() {
		sb := Get()
		sb.WriteInt(math.MinInt64)
		sb.WriteByte(' ')
		sb.WriteInt(math.MaxInt64)
		sb.WriteByte(' ')
		sb.WriteUint(math.MaxUint64)
		got = sb.String()
	})
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
	if allocs != 1 {
		t.Errorf("allocs = %v; want 1", allocs)
	}
}

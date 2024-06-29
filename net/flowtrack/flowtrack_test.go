// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package flowtrack

import (
	"encoding/json"
	"net/netip"
	"testing"

	"tailscale.com/tstest"
	"tailscale.com/types/ipproto"
)

func TestCache(t *testing.T) {
	c := &Cache[int]{MaxEntries: 2}

	k1 := MakeTuple(0, netip.MustParseAddrPort("1.1.1.1:1"), netip.MustParseAddrPort("1.1.1.1:1"))
	k2 := MakeTuple(0, netip.MustParseAddrPort("1.1.1.1:1"), netip.MustParseAddrPort("2.2.2.2:2"))
	k3 := MakeTuple(0, netip.MustParseAddrPort("1.1.1.1:1"), netip.MustParseAddrPort("3.3.3.3:3"))
	k4 := MakeTuple(0, netip.MustParseAddrPort("1.1.1.1:1"), netip.MustParseAddrPort("4.4.4.4:4"))

	wantLen := func(want int) {
		t.Helper()
		if got := c.Len(); got != want {
			t.Fatalf("Len = %d; want %d", got, want)
		}
	}
	wantVal := func(key Tuple, want int) {
		t.Helper()
		got, ok := c.Get(key)
		if !ok {
			t.Fatalf("Get(%q) failed; want value %v", key, want)
		}
		if *got != want {
			t.Fatalf("Get(%q) = %v; want %v", key, got, want)
		}
	}
	wantMissing := func(key Tuple) {
		t.Helper()
		if got, ok := c.Get(key); ok {
			t.Fatalf("Get(%q) = %v; want absent from cache", key, got)
		}
	}

	wantLen(0)
	c.RemoveOldest() // shouldn't panic
	c.Remove(k4)     // shouldn't panic

	c.Add(k1, 1)
	wantLen(1)
	c.Add(k2, 2)
	wantLen(2)
	c.Add(k3, 3)
	wantLen(2) // hit the max

	wantMissing(k1)
	c.Remove(k1)
	wantLen(2) // no change; k1 should've been the deleted one per LRU

	wantVal(k3, 3)

	wantVal(k2, 2)
	c.Remove(k2)
	wantLen(1)
	wantMissing(k2)

	c.Add(k3, 30)
	wantVal(k3, 30)
	wantLen(1)

	err := tstest.MinAllocsPerRun(t, 0, func() {
		got, ok := c.Get(k3)
		if !ok {
			t.Fatal("missing k3")
		}
		if *got != 30 {
			t.Fatalf("got = %d; want 30", got)
		}
	})
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkMapKeys(b *testing.B) {
	b.Run("typed", func(b *testing.B) {
		c := &Cache[struct{}]{MaxEntries: 1000}
		var t Tuple
		for proto := range 20 {
			t = Tuple{proto: ipproto.Proto(proto), src: netip.MustParseAddr("1.1.1.1").As16(), srcPort: 1, dst: netip.MustParseAddr("1.1.1.1").As16(), dstPort: 1}
			c.Add(t, struct{}{})
		}
		for i := 0; i < b.N; i++ {
			_, ok := c.Get(t)
			if !ok {
				b.Fatal("missing key")
			}
		}
	})
}

func TestStringJSON(t *testing.T) {
	v := MakeTuple(123,
		netip.MustParseAddrPort("1.2.3.4:5"),
		netip.MustParseAddrPort("6.7.8.9:10"))

	if got, want := v.String(), "(IPProto-123 1.2.3.4:5 => 6.7.8.9:10)"; got != want {
		t.Errorf("String = %q; want %q", got, want)
	}

	got, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"proto":123,"src":"1.2.3.4:5","dst":"6.7.8.9:10"}`
	if string(got) != want {
		t.Errorf("Marshal = %q; want %q", got, want)
	}

	var back Tuple
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatal(err)
	}
	if back != v {
		t.Errorf("back = %v; want %v", back, v)
	}
}

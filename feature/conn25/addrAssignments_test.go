// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/tstest"
)

func TestAssignmentsExpire(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Now()})
	assignments := addrAssignments{clock: clock}
	as := &addrs{
		dst:     netip.MustParseAddr("0.0.0.1"),
		magic:   netip.MustParseAddr("0.0.0.2"),
		transit: netip.MustParseAddr("0.0.0.3"),
		app:     "a",
		domain:  "example.com.",
	}
	err := assignments.insert(as)
	if err != nil {
		t.Fatal(err)
	}
	// Time has not passed since the insert, the assignment should be returned.
	foundAs, ok := assignments.lookupByMagicIP(as.magic)
	if !ok {
		t.Fatal("expected to find")
	}
	if foundAs.dst != as.dst {
		t.Fatalf("want %v; got %v", as.dst, foundAs.dst)
	}
	// and we cannot insert over the addresses
	err = assignments.insert(as)
	if err == nil {
		t.Fatal("expected an error but got nil")
	}
	// We should only be able to write old addresses again if they've been removed from the maps (eg with popExpired).
	clock.Advance(defaultExpiry * 2)
	err = assignments.insert(as)
	if err == nil {
		t.Fatal("expected an error but got nil")
	}
}

func TestPopExpired(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Now()})
	assignments := addrAssignments{clock: clock}
	makeAndAddAddrs := func(n int) *addrs {
		t.Helper()
		as := &addrs{
			dst:     netip.MustParseAddr(fmt.Sprintf("0.0.1.%d", n)),
			magic:   netip.MustParseAddr(fmt.Sprintf("0.0.2.%d", n)),
			transit: netip.MustParseAddr(fmt.Sprintf("0.0.3.%d", n)),
			app:     "a",
			domain:  "example.com.",
		}
		err := assignments.insert(as)
		if err != nil {
			t.Fatal(err)
		}
		return as
	}
	// cmp.Diff addrs ignoring expiresAt
	doDiff := func(want, got *addrs) string {
		t.Helper()
		return cmp.Diff(
			want,
			got,
			cmp.AllowUnexported(addrs{}),
			cmpopts.EquateComparable(netip.Addr{}),
			cmpopts.IgnoreFields(addrs{}, "expiresAt"),
		)
	}
	testAddrs := []*addrs{}
	for i := range 2 {
		testAddrs = append(testAddrs, makeAndAddAddrs(i+1))
		clock.Advance(1 * time.Second)
	}
	if len(assignments.byMagicIP) != 2 {
		t.Fatalf("test setup wrong")
	}

	nn := assignments.popExpired(clock.Now())
	if diff := doDiff(nil, nn); diff != "" {
		t.Fatalf("only expired addresses are removed: %s", diff)
	}
	if len(assignments.byMagicIP) != 2 {
		t.Fatalf("nothing should have been removed")
	}

	clock.Advance(2 * defaultExpiry) // all addrs are now expired

	want := testAddrs[0]
	nn = assignments.popExpired(clock.Now())
	if diff := doDiff(want, nn); diff != "" {
		t.Fatal(diff)
	}
	if len(assignments.byMagicIP) != 1 {
		t.Fatalf("an assignment should have been removed")
	}

	want = testAddrs[1]
	nn = assignments.popExpired(clock.Now())
	if diff := doDiff(want, nn); diff != "" {
		t.Fatal(diff)
	}
	if len(assignments.byMagicIP) != 0 {
		t.Fatalf("an assignment should have been removed")
	}

	nn = assignments.popExpired(clock.Now())
	if diff := doDiff(nil, nn); diff != "" {
		t.Fatal(diff)
	}
	if len(assignments.byMagicIP) != 0 {
		t.Fatalf("there should have been no change")
	}
}

func TestPopExpiredHandlesExpiresAtChanges(t *testing.T) {
	expiryInterval := time.Second * 5
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Now()})
	assignments := addrAssignments{clock: clock}
	makeAndAddAddrs := func(n int) *addrs {
		t.Helper()
		as := &addrs{
			dst:     netip.MustParseAddr(fmt.Sprintf("0.0.1.%d", n)),
			magic:   netip.MustParseAddr(fmt.Sprintf("0.0.2.%d", n)),
			transit: netip.MustParseAddr(fmt.Sprintf("0.0.3.%d", n)),
			app:     "a",
			domain:  "example.com.",
		}
		err := assignments.insertWithExpiry(as, expiryInterval)
		if err != nil {
			t.Fatal(err)
		}
		return as
	}
	addresses := []*addrs{}
	// t = 0
	for i := range 10 {
		addresses = append(addresses, makeAndAddAddrs(i)) // expires at t=i+5
		// We track the next addr to expire with a heap. updateExpiry changes the heap invariant.
		// Twiddling the addrs in this particular way (updating item 1 after inserting 7) shows that
		// we are fixing the heap after updating the invariant (if we weren't the test would fail).
		if i == 6 {
			assignments.updateExpiry(addresses[1], 20*time.Second) // addresses[1] expires at t=26
		}
		clock.Advance(time.Second)
	}
	// t = 10

	expectedOrder := []int{0, 2, 3, 4, 5, 6, 7, 8, 9, 1}
	i := 0
	for tick := range 18 {
		a := assignments.popExpired(clock.Now())
		if a != nil {
			expectedIdx := expectedOrder[i]
			if a != addresses[expectedIdx] {
				t.Fatalf("want %v, got %v at tick=%v", addresses[expectedIdx].magic, a.magic, tick)
			}
			i++
		}
		clock.Advance(time.Second)
	}
	if len(assignments.byMagicIP) != 0 {
		t.Fatalf("expected assignments to be exhausted")
	}
}

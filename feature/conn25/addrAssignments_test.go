// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"tailscale.com/tstest"
)

func TestAssignmentsExpire(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Now()})
	assignments := addrAssignments{clock: clock}
	as := addrs{
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
	// After a time greater than the default expiry passes, the assignment should
	// not be returned.
	clock.Advance(defaultExpiry * 2)
	foundAsAfter, okAfter := assignments.lookupByMagicIP(as.magic)
	if okAfter {
		t.Fatal("expected not to find (expired)")
	}
	if foundAsAfter.isValid() {
		t.Fatal("expected zero val")
	}
	// Now we can reuse the addresses
	err = assignments.insert(as)
	if err != nil {
		t.Fatal(err)
	}
	foundAs, ok = assignments.lookupByMagicIP(as.magic)
	if !ok {
		t.Fatal("expected to find")
	}
	if foundAs.dst != as.dst {
		t.Fatalf("want %v; got %v", as.dst, foundAs.dst)
	}
	if !foundAs.expiresAt.After(clock.Now()) {
		t.Fatalf("expected foundAs to expire after now")
	}
}

func TestRemoveExpireds(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Now()})
	assignments := addrAssignments{clock: clock}
	assertAllIndexesHaveLength := func(want int) {
		t.Helper()
		if len(assignments.byDomainDst) != want {
			t.Fatalf("wanted byDomainDst index to have len %d, got: %d", want, len(assignments.byDomainDst))
		}
		if len(assignments.byMagicIP) != want {
			t.Fatalf("wanted byMagicIP index to have len %d, got: %d", want, len(assignments.byMagicIP))
		}
		if len(assignments.byTransitIP) != want {
			t.Fatalf("wanted byTransitIP index to have len %d want, got: %d", want, len(assignments.byTransitIP))
		}
	}
	makeAddrs := func(i int) addrs {
		return addrs{
			dst:     netip.MustParseAddr(fmt.Sprintf("0.0.0.%d", i)),
			magic:   netip.MustParseAddr(fmt.Sprintf("0.0.1.%d", i)),
			transit: netip.MustParseAddr(fmt.Sprintf("0.0.2.%d", i)),
			app:     "a",
			domain:  "example.com.",
		}
	}
	as := makeAddrs(1)
	err := assignments.insert(as)
	if err != nil {
		t.Fatal(err)
	}
	insertedAs, ok := assignments.lookupByMagicIP(as.magic)
	if !ok {
		t.Fatal("expected to find inserted addr")
	}
	// more than the default expiry time has passed
	clock.Advance(defaultExpiry * 2)
	expiredAddrs := assignments.removeExpiredAddrs()
	if len(expiredAddrs) != 1 || expiredAddrs[0] != insertedAs {
		t.Fatalf("wanted inserted addrs to be returned, got: %v", expiredAddrs)
	}
	assertAllIndexesHaveLength(0)

	// removing with 0 entries is ok
	expiredAddrs = assignments.removeExpiredAddrs()
	if len(expiredAddrs) != 0 {
		t.Fatalf("want 0; got %d", len(expiredAddrs))
	}
	assertAllIndexesHaveLength(0)

	// removes only expired addrss
	as = makeAddrs(2)
	if err := assignments.insert(as); err != nil { // t = 0
		t.Fatal(err)
	}
	clock.Advance(1 * time.Hour)
	if err := assignments.insert(makeAddrs(3)); err != nil { // t = 1
		t.Fatal(err)
	}
	clock.Advance(24 * time.Hour)
	if err := assignments.insert(makeAddrs(4)); err != nil { // t = 25
		t.Fatal(err)
	}
	clock.Advance(1 * time.Hour)
	if err := assignments.insert(makeAddrs(5)); err != nil { // t = 26
		t.Fatal(err)
	}
	clock.Advance(24 * time.Hour) // t = 50, default expiry is 48 hours, so addrs inserted at t 0 and 1 are past expiry now
	assertAllIndexesHaveLength(4)

	expiredAddrs = assignments.removeExpiredAddrs()
	if len(expiredAddrs) != 2 {
		t.Fatalf("want 2; got %d", len(expiredAddrs))
	}
	assertAllIndexesHaveLength(2)
	slices.SortFunc(expiredAddrs, func(a, b addrs) int {
		return a.magic.Compare(b.magic)
	})
	want := netip.MustParseAddr("0.0.1.2")
	if expiredAddrs[0].magic != want {
		t.Fatalf("want %v; got %v", want, expiredAddrs[0].magic)
	}
	want = netip.MustParseAddr("0.0.1.3")
	if expiredAddrs[1].magic != want {
		t.Fatalf("want %v; got %v", want, expiredAddrs[1].magic)
	}
}

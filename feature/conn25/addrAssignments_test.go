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
	want := &addrs{} // invalid addr
	if diff := doDiff(want, nn); diff != "" {
		t.Fatalf("only expired addresses are removed: %s", diff)
	}
	if len(assignments.byMagicIP) != 2 {
		t.Fatalf("nothing should have been removed")
	}
	if nn.isValid() {
		t.Fatal("empty addrs should be invalid")
	}

	clock.Advance(2 * defaultExpiry) // all addrs are now expired

	want = testAddrs[0]
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

	want = &addrs{}
	nn = assignments.popExpired(clock.Now())
	if diff := doDiff(want, nn); diff != "" {
		t.Fatal(diff)
	}
	if len(assignments.byMagicIP) != 0 {
		t.Fatalf("there should have been no change")
	}
}

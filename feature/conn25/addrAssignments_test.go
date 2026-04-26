// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"net/netip"
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

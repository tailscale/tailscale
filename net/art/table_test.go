// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package art

import (
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"net/netip"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestRegression(t *testing.T) {
	// These tests are specific triggers for subtle correctness issues
	// that came up during initial implementation. Even if they seem
	// arbitrary, please do not clean them up. They are checking edge
	// cases that are very easy to get wrong, and quite difficult for
	// the other statistical tests to trigger promptly.

	t.Run("prefixes_aligned_on_stride_boundary", func(t *testing.T) {
		// Regression test for computePrefixSplit called with equal
		// arguments.
		tbl := &Table[int]{}
		slow := slowPrefixTable[int]{}
		p := netip.MustParsePrefix

		tbl.Insert(p("226.205.197.0/24"), 1)
		slow.insert(p("226.205.197.0/24"), 1)
		tbl.Insert(p("226.205.0.0/16"), 2)
		slow.insert(p("226.205.0.0/16"), 2)

		probe := netip.MustParseAddr("226.205.121.152")
		got, gotOK := tbl.Get(probe)
		want, wantOK := slow.get(probe)
		if !getsEqual(got, gotOK, want, wantOK) {
			t.Fatalf("got (%v, %v), want (%v, %v)", got, gotOK, want, wantOK)
		}
	})

	t.Run("parent_prefix_inserted_in_different_orders", func(t *testing.T) {
		// Regression test for the off-by-one correction applied
		// within computePrefixSplit.
		t1, t2 := &Table[int]{}, &Table[int]{}
		p := netip.MustParsePrefix

		t1.Insert(p("136.20.0.0/16"), 1)
		t1.Insert(p("136.20.201.62/32"), 2)

		t2.Insert(p("136.20.201.62/32"), 2)
		t2.Insert(p("136.20.0.0/16"), 1)

		a := netip.MustParseAddr("136.20.54.139")
		got1, ok1 := t1.Get(a)
		got2, ok2 := t2.Get(a)
		if !getsEqual(got1, ok1, got2, ok2) {
			t.Errorf("Get(%q) is insertion order dependent: t1=(%v, %v), t2=(%v, %v)", a, got1, ok1, got2, ok2)
		}
	})
}

func TestComputePrefixSplit(t *testing.T) {
	// These tests are partially redundant with other tests. Please
	// keep them anyway. computePrefixSplit's behavior is remarkably
	// subtle, and all the test cases listed below come from
	// hard-earned debugging of malformed route tables.

	var tests = []struct {
		// prefixA can be a /8, /16 or /24 (v4).
		// prefixB can be anything /9 or more specific.
		prefixA, prefixB string
		lastCommon       string
		aStride, bStride uint8
	}{
		{"192.168.1.0/24", "192.168.5.5/32", "192.168.0.0/16", 1, 5},
		{"192.168.129.0/24", "192.168.128.0/17", "192.168.0.0/16", 129, 128},
		{"192.168.5.0/24", "192.168.0.0/16", "192.0.0.0/8", 168, 168},
		{"192.168.0.0/16", "192.168.0.0/16", "192.0.0.0/8", 168, 168},
		{"ff:aaaa:aaaa::1/128", "ff:aaaa::/120", "ff:aaaa::/32", 170, 0},
	}

	for _, test := range tests {
		a, b := netip.MustParsePrefix(test.prefixA), netip.MustParsePrefix(test.prefixB)
		gotLastCommon, gotAStride, gotBStride := computePrefixSplit(a, b)
		if want := netip.MustParsePrefix(test.lastCommon); gotLastCommon != want || gotAStride != test.aStride || gotBStride != test.bStride {
			t.Errorf("computePrefixSplit(%q, %q) = %s, %d, %d; want %s, %d, %d", a, b, gotLastCommon, gotAStride, gotBStride, want, test.aStride, test.bStride)
		}
	}
}

func TestInsert(t *testing.T) {
	tbl := &Table[int]{}
	p := netip.MustParsePrefix

	// Create a new leaf strideTable, with compressed path
	tbl.Insert(p("192.168.0.1/32"), 1)
	checkRoutes(t, tbl, []tableTest{
		{"192.168.0.1", 1},
		{"192.168.0.2", -1},
		{"192.168.0.3", -1},
		{"192.168.0.255", -1},
		{"192.168.1.1", -1},
		{"192.170.1.1", -1},
		{"192.180.0.1", -1},
		{"192.180.3.5", -1},
		{"10.0.0.5", -1},
		{"10.0.0.15", -1},
	})

	// Insert into previous leaf, no tree changes
	tbl.Insert(p("192.168.0.2/32"), 2)
	checkRoutes(t, tbl, []tableTest{
		{"192.168.0.1", 1},
		{"192.168.0.2", 2},
		{"192.168.0.3", -1},
		{"192.168.0.255", -1},
		{"192.168.1.1", -1},
		{"192.170.1.1", -1},
		{"192.180.0.1", -1},
		{"192.180.3.5", -1},
		{"10.0.0.5", -1},
		{"10.0.0.15", -1},
	})

	// Insert into previous leaf, unaligned prefix covering the /32s
	tbl.Insert(p("192.168.0.0/26"), 7)
	checkRoutes(t, tbl, []tableTest{
		{"192.168.0.1", 1},
		{"192.168.0.2", 2},
		{"192.168.0.3", 7},
		{"192.168.0.255", -1},
		{"192.168.1.1", -1},
		{"192.170.1.1", -1},
		{"192.180.0.1", -1},
		{"192.180.3.5", -1},
		{"10.0.0.5", -1},
		{"10.0.0.15", -1},
	})

	// Create a different leaf elsewhere
	tbl.Insert(p("10.0.0.0/27"), 3)
	checkRoutes(t, tbl, []tableTest{
		{"192.168.0.1", 1},
		{"192.168.0.2", 2},
		{"192.168.0.3", 7},
		{"192.168.0.255", -1},
		{"192.168.1.1", -1},
		{"192.170.1.1", -1},
		{"192.180.0.1", -1},
		{"192.180.3.5", -1},
		{"10.0.0.5", 3},
		{"10.0.0.15", 3},
	})

	// Insert that creates a new intermediate table and a new child
	tbl.Insert(p("192.168.1.1/32"), 4)
	checkRoutes(t, tbl, []tableTest{
		{"192.168.0.1", 1},
		{"192.168.0.2", 2},
		{"192.168.0.3", 7},
		{"192.168.0.255", -1},
		{"192.168.1.1", 4},
		{"192.170.1.1", -1},
		{"192.180.0.1", -1},
		{"192.180.3.5", -1},
		{"10.0.0.5", 3},
		{"10.0.0.15", 3},
	})

	// Insert that creates a new intermediate table but no new child
	tbl.Insert(p("192.170.0.0/16"), 5)
	checkRoutes(t, tbl, []tableTest{
		{"192.168.0.1", 1},
		{"192.168.0.2", 2},
		{"192.168.0.3", 7},
		{"192.168.0.255", -1},
		{"192.168.1.1", 4},
		{"192.170.1.1", 5},
		{"192.180.0.1", -1},
		{"192.180.3.5", -1},
		{"10.0.0.5", 3},
		{"10.0.0.15", 3},
	})

	// New leaf in a different subtree, so the next insert can test a
	// variant of decompression.
	tbl.Insert(p("192.180.0.1/32"), 8)
	checkRoutes(t, tbl, []tableTest{
		{"192.168.0.1", 1},
		{"192.168.0.2", 2},
		{"192.168.0.3", 7},
		{"192.168.0.255", -1},
		{"192.168.1.1", 4},
		{"192.170.1.1", 5},
		{"192.180.0.1", 8},
		{"192.180.3.5", -1},
		{"10.0.0.5", 3},
		{"10.0.0.15", 3},
	})

	// Insert that creates a new intermediate table but no new child,
	// with an unaligned intermediate
	tbl.Insert(p("192.180.0.0/21"), 9)
	checkRoutes(t, tbl, []tableTest{
		{"192.168.0.1", 1},
		{"192.168.0.2", 2},
		{"192.168.0.3", 7},
		{"192.168.0.255", -1},
		{"192.168.1.1", 4},
		{"192.170.1.1", 5},
		{"192.180.0.1", 8},
		{"192.180.3.5", 9},
		{"10.0.0.5", 3},
		{"10.0.0.15", 3},
	})

	// Insert a default route, those have their own codepath.
	tbl.Insert(p("0.0.0.0/0"), 6)
	checkRoutes(t, tbl, []tableTest{
		{"192.168.0.1", 1},
		{"192.168.0.2", 2},
		{"192.168.0.3", 7},
		{"192.168.0.255", 6},
		{"192.168.1.1", 4},
		{"192.170.1.1", 5},
		{"192.180.0.1", 8},
		{"192.180.3.5", 9},
		{"10.0.0.5", 3},
		{"10.0.0.15", 3},
	})

	// Now all of the above again, but for IPv6.

	// Create a new leaf strideTable, with compressed path
	tbl.Insert(p("ff:aaaa::1/128"), 1)
	checkRoutes(t, tbl, []tableTest{
		{"ff:aaaa::1", 1},
		{"ff:aaaa::2", -1},
		{"ff:aaaa::3", -1},
		{"ff:aaaa::255", -1},
		{"ff:aaaa:aaaa::1", -1},
		{"ff:aaaa:aaaa:bbbb::1", -1},
		{"ff:cccc::1", -1},
		{"ff:cccc::ff", -1},
		{"ffff:bbbb::5", -1},
		{"ffff:bbbb::15", -1},
	})

	// Insert into previous leaf, no tree changes
	tbl.Insert(p("ff:aaaa::2/128"), 2)
	checkRoutes(t, tbl, []tableTest{
		{"ff:aaaa::1", 1},
		{"ff:aaaa::2", 2},
		{"ff:aaaa::3", -1},
		{"ff:aaaa::255", -1},
		{"ff:aaaa:aaaa::1", -1},
		{"ff:aaaa:aaaa:bbbb::1", -1},
		{"ff:cccc::1", -1},
		{"ff:cccc::ff", -1},
		{"ffff:bbbb::5", -1},
		{"ffff:bbbb::15", -1},
	})

	// Insert into previous leaf, unaligned prefix covering the /128s
	tbl.Insert(p("ff:aaaa::/125"), 7)
	checkRoutes(t, tbl, []tableTest{
		{"ff:aaaa::1", 1},
		{"ff:aaaa::2", 2},
		{"ff:aaaa::3", 7},
		{"ff:aaaa::255", -1},
		{"ff:aaaa:aaaa::1", -1},
		{"ff:aaaa:aaaa:bbbb::1", -1},
		{"ff:cccc::1", -1},
		{"ff:cccc::ff", -1},
		{"ffff:bbbb::5", -1},
		{"ffff:bbbb::15", -1},
	})

	// Create a different leaf elsewhere
	tbl.Insert(p("ffff:bbbb::/120"), 3)
	checkRoutes(t, tbl, []tableTest{
		{"ff:aaaa::1", 1},
		{"ff:aaaa::2", 2},
		{"ff:aaaa::3", 7},
		{"ff:aaaa::255", -1},
		{"ff:aaaa:aaaa::1", -1},
		{"ff:aaaa:aaaa:bbbb::1", -1},
		{"ff:cccc::1", -1},
		{"ff:cccc::ff", -1},
		{"ffff:bbbb::5", 3},
		{"ffff:bbbb::15", 3},
	})

	// Insert that creates a new intermediate table and a new child
	tbl.Insert(p("ff:aaaa:aaaa::1/128"), 4)
	checkRoutes(t, tbl, []tableTest{
		{"ff:aaaa::1", 1},
		{"ff:aaaa::2", 2},
		{"ff:aaaa::3", 7},
		{"ff:aaaa::255", -1},
		{"ff:aaaa:aaaa::1", 4},
		{"ff:aaaa:aaaa:bbbb::1", -1},
		{"ff:cccc::1", -1},
		{"ff:cccc::ff", -1},
		{"ffff:bbbb::5", 3},
		{"ffff:bbbb::15", 3},
	})

	// Insert that creates a new intermediate table but no new child
	tbl.Insert(p("ff:aaaa:aaaa:bb00::/56"), 5)
	checkRoutes(t, tbl, []tableTest{
		{"ff:aaaa::1", 1},
		{"ff:aaaa::2", 2},
		{"ff:aaaa::3", 7},
		{"ff:aaaa::255", -1},
		{"ff:aaaa:aaaa::1", 4},
		{"ff:aaaa:aaaa:bbbb::1", 5},
		{"ff:cccc::1", -1},
		{"ff:cccc::ff", -1},
		{"ffff:bbbb::5", 3},
		{"ffff:bbbb::15", 3},
	})

	// New leaf in a different subtree, so the next insert can test a
	// variant of decompression.
	tbl.Insert(p("ff:cccc::1/128"), 8)
	checkRoutes(t, tbl, []tableTest{
		{"ff:aaaa::1", 1},
		{"ff:aaaa::2", 2},
		{"ff:aaaa::3", 7},
		{"ff:aaaa::255", -1},
		{"ff:aaaa:aaaa::1", 4},
		{"ff:aaaa:aaaa:bbbb::1", 5},
		{"ff:cccc::1", 8},
		{"ff:cccc::ff", -1},
		{"ffff:bbbb::5", 3},
		{"ffff:bbbb::15", 3},
	})

	// Insert that creates a new intermediate table but no new child,
	// with an unaligned intermediate
	tbl.Insert(p("ff:cccc::/37"), 9)
	checkRoutes(t, tbl, []tableTest{
		{"ff:aaaa::1", 1},
		{"ff:aaaa::2", 2},
		{"ff:aaaa::3", 7},
		{"ff:aaaa::255", -1},
		{"ff:aaaa:aaaa::1", 4},
		{"ff:aaaa:aaaa:bbbb::1", 5},
		{"ff:cccc::1", 8},
		{"ff:cccc::ff", 9},
		{"ffff:bbbb::5", 3},
		{"ffff:bbbb::15", 3},
	})

	// Insert a default route, those have their own codepath.
	tbl.Insert(p("::/0"), 6)
	checkRoutes(t, tbl, []tableTest{
		{"ff:aaaa::1", 1},
		{"ff:aaaa::2", 2},
		{"ff:aaaa::3", 7},
		{"ff:aaaa::255", 6},
		{"ff:aaaa:aaaa::1", 4},
		{"ff:aaaa:aaaa:bbbb::1", 5},
		{"ff:cccc::1", 8},
		{"ff:cccc::ff", 9},
		{"ffff:bbbb::5", 3},
		{"ffff:bbbb::15", 3},
	})
}

func TestDelete(t *testing.T) {
	t.Parallel()
	p := netip.MustParsePrefix

	t.Run("prefix_in_root", func(t *testing.T) {
		// Add/remove prefix from root table.
		tbl := &Table[int]{}
		checkSize(t, tbl, 2)

		tbl.Insert(p("10.0.0.0/8"), 1)
		checkRoutes(t, tbl, []tableTest{
			{"10.0.0.1", 1},
			{"255.255.255.255", -1},
		})
		checkSize(t, tbl, 2)
		tbl.Delete(p("10.0.0.0/8"))
		checkRoutes(t, tbl, []tableTest{
			{"10.0.0.1", -1},
			{"255.255.255.255", -1},
		})
		checkSize(t, tbl, 2)
	})

	t.Run("prefix_in_leaf", func(t *testing.T) {
		// Create, then delete a single leaf table.
		tbl := &Table[int]{}
		checkSize(t, tbl, 2)

		tbl.Insert(p("192.168.0.1/32"), 1)
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"255.255.255.255", -1},
		})
		checkSize(t, tbl, 3)
		tbl.Delete(p("192.168.0.1/32"))
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", -1},
			{"255.255.255.255", -1},
		})
		checkSize(t, tbl, 2)
	})

	t.Run("intermediate_no_routes", func(t *testing.T) {
		// Create an intermediate with 2 children, then delete one leaf.
		tbl := &Table[int]{}
		checkSize(t, tbl, 2)
		tbl.Insert(p("192.168.0.1/32"), 1)
		tbl.Insert(p("192.180.0.1/32"), 2)
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.180.0.1", 2},
			{"192.40.0.1", -1},
		})
		checkSize(t, tbl, 5) // 2 roots, 1 intermediate, 2 leaves
		tbl.Delete(p("192.180.0.1/32"))
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.180.0.1", -1},
			{"192.40.0.1", -1},
		})
		checkSize(t, tbl, 3) // 2 roots, 1 leaf
	})

	t.Run("intermediate_with_route", func(t *testing.T) {
		// Same, but the intermediate carries a route as well.
		tbl := &Table[int]{}
		checkSize(t, tbl, 2)
		tbl.Insert(p("192.168.0.1/32"), 1)
		tbl.Insert(p("192.180.0.1/32"), 2)
		tbl.Insert(p("192.0.0.0/10"), 3)
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.180.0.1", 2},
			{"192.40.0.1", 3},
			{"192.255.0.1", -1},
		})
		checkSize(t, tbl, 5) // 2 roots, 1 intermediate, 2 leaves
		tbl.Delete(p("192.180.0.1/32"))
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.180.0.1", -1},
			{"192.40.0.1", 3},
			{"192.255.0.1", -1},
		})
		checkSize(t, tbl, 4) // 2 roots, 1 intermediate w/route, 1 leaf
	})

	t.Run("intermediate_many_leaves", func(t *testing.T) {
		// Intermediate with 3 leaves, then delete one leaf.
		tbl := &Table[int]{}
		checkSize(t, tbl, 2)
		tbl.Insert(p("192.168.0.1/32"), 1)
		tbl.Insert(p("192.180.0.1/32"), 2)
		tbl.Insert(p("192.200.0.1/32"), 3)
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.180.0.1", 2},
			{"192.200.0.1", 3},
			{"192.255.0.1", -1},
		})
		checkSize(t, tbl, 6) // 2 roots, 1 intermediate, 3 leaves
		tbl.Delete(p("192.180.0.1/32"))
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.180.0.1", -1},
			{"192.200.0.1", 3},
			{"192.255.0.1", -1},
		})
		checkSize(t, tbl, 5) // 2 roots, 1 intermediate, 2 leaves
	})

	t.Run("nosuchprefix_missing_child", func(t *testing.T) {
		// Delete non-existent prefix, missing strideTable path.
		tbl := &Table[int]{}
		checkSize(t, tbl, 2)
		tbl.Insert(p("192.168.0.1/32"), 1)
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.255.0.1", -1},
		})
		checkSize(t, tbl, 3)          // 2 roots, 1 leaf
		tbl.Delete(p("200.0.0.0/32")) // lookup miss in root
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.255.0.1", -1},
		})
		checkSize(t, tbl, 3) // 2 roots, 1 leaf
	})

	t.Run("nosuchprefix_wrong_turn", func(t *testing.T) {
		// Delete non-existent prefix, strideTable path exists but
		// with a wrong turn.
		tbl := &Table[int]{}
		checkSize(t, tbl, 2)
		tbl.Insert(p("192.168.0.1/32"), 1)
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.255.0.1", -1},
		})
		checkSize(t, tbl, 3)           // 2 roots, 1 leaf
		tbl.Delete(p("192.40.0.0/32")) // finds wrong child
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.255.0.1", -1},
		})
		checkSize(t, tbl, 3) // 2 roots, 1 leaf
	})

	t.Run("nosuchprefix_not_in_leaf", func(t *testing.T) {
		// Delete non-existent prefix, strideTable path exists but
		// leaf doesn't contain route.
		tbl := &Table[int]{}
		checkSize(t, tbl, 2)
		tbl.Insert(p("192.168.0.1/32"), 1)
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.255.0.1", -1},
		})
		checkSize(t, tbl, 3)            // 2 roots, 1 leaf
		tbl.Delete(p("192.168.0.5/32")) // right leaf, no route
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.255.0.1", -1},
		})
		checkSize(t, tbl, 3) // 2 roots, 1 leaf
	})

	t.Run("intermediate_with_deleted_route", func(t *testing.T) {
		// Intermediate table loses its last route and becomes
		// compactable.
		tbl := &Table[int]{}
		checkSize(t, tbl, 2)
		tbl.Insert(p("192.168.0.1/32"), 1)
		tbl.Insert(p("192.168.0.0/22"), 2)
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.168.0.2", 2},
			{"192.255.0.1", -1},
		})
		checkSize(t, tbl, 4) // 2 roots, 1 intermediate w/route, 1 leaf
		tbl.Delete(p("192.168.0.0/22"))
		checkRoutes(t, tbl, []tableTest{
			{"192.168.0.1", 1},
			{"192.168.0.2", -1},
			{"192.255.0.1", -1},
		})
		checkSize(t, tbl, 3) // 2 roots, 1 leaf
	})

	t.Run("default_route", func(t *testing.T) {
		// Default routes have a special case in the code.
		tbl := &Table[int]{}

		tbl.Insert(p("0.0.0.0/0"), 1)
		tbl.Delete(p("0.0.0.0/0"))

		checkRoutes(t, tbl, []tableTest{
			{"1.2.3.4", -1},
		})
		checkSize(t, tbl, 2) // 2 roots
	})
}

func TestInsertCompare(t *testing.T) {
	// Create large route tables repeatedly, and compare Table's
	// behavior to a naive and slow but correct implementation.
	t.Parallel()
	pfxs := randomPrefixes(10_000)

	slow := slowPrefixTable[int]{pfxs}
	fast := Table[int]{}

	for _, pfx := range pfxs {
		fast.Insert(pfx.pfx, pfx.val)
	}

	if debugInsert {
		t.Log(fast.debugSummary())
	}

	seenVals4 := map[int]bool{}
	seenVals6 := map[int]bool{}
	for range 10_000 {
		a := randomAddr()
		slowVal, slowOK := slow.get(a)
		fastVal, fastOK := fast.Get(a)
		if !getsEqual(slowVal, slowOK, fastVal, fastOK) {
			t.Fatalf("get(%q) = (%v, %v), want (%v, %v)", a, fastVal, fastOK, slowVal, slowOK)
		}
		if a.Is6() {
			seenVals6[fastVal] = true
		} else {
			seenVals4[fastVal] = true
		}
	}

	// Empirically, 10k probes into 5k v4 prefixes and 5k v6 prefixes results in
	// ~1k distinct values for v4 and ~300 for v6. distinct routes. This sanity
	// check that we didn't just return a single route for everything should be
	// very generous indeed.
	if cnt := len(seenVals4); cnt < 10 {
		t.Fatalf("saw %d distinct v4 route results, statistically expected ~1000", cnt)
	}
	if cnt := len(seenVals6); cnt < 10 {
		t.Fatalf("saw %d distinct v6 route results, statistically expected ~300", cnt)
	}
}

func TestInsertShuffled(t *testing.T) {
	// The order in which you insert prefixes into a route table
	// should not matter, as long as you're inserting the same set of
	// routes. Verify that this is true, because ART does execute
	// vastly different code depending on the order of insertion, even
	// if the end result is identical.
	//
	// If you're here because this package's tests are slow and you
	// want to make them faster, please do not delete this test (or
	// any test, really). It may seem excessive to test this, but
	// these shuffle tests found a lot of very nasty edge cases during
	// development, and you _really_ don't want to be debugging a
	// faulty route table in production.
	t.Parallel()
	pfxs := randomPrefixes(1000)
	var pfxs2 []slowPrefixEntry[int]

	defer func() {
		if t.Failed() {
			t.Logf("pre-shuffle: %#v", pfxs)
			t.Logf("post-shuffle: %#v", pfxs2)
		}
	}()

	for range 10 {
		pfxs2 := append([]slowPrefixEntry[int](nil), pfxs...)
		rand.Shuffle(len(pfxs2), func(i, j int) { pfxs2[i], pfxs2[j] = pfxs2[j], pfxs2[i] })

		addrs := make([]netip.Addr, 0, 10_000)
		for range 10_000 {
			addrs = append(addrs, randomAddr())
		}

		rt := Table[int]{}
		rt2 := Table[int]{}

		for _, pfx := range pfxs {
			rt.Insert(pfx.pfx, pfx.val)
		}
		for _, pfx := range pfxs2 {
			rt2.Insert(pfx.pfx, pfx.val)
		}

		for _, a := range addrs {
			val1, ok1 := rt.Get(a)
			val2, ok2 := rt2.Get(a)
			if !getsEqual(val1, ok1, val2, ok2) {
				t.Fatalf("get(%q) = (%v, %v), want (%v, %v)", a, val2, ok2, val1, ok1)
			}
		}
	}
}

func TestDeleteCompare(t *testing.T) {
	// Create large route tables repeatedly, delete half of their
	// prefixes, and compare Table's behavior to a naive and slow but
	// correct implementation.
	t.Parallel()

	const (
		numPrefixes  = 10_000 // total prefixes to insert (test deletes 50% of them)
		numPerFamily = numPrefixes / 2
		deleteCut    = numPerFamily / 2
		numProbes    = 10_000 // random addr lookups to do
	)

	// We have to do this little dance instead of just using allPrefixes,
	// because we want pfxs and toDelete to be non-overlapping sets.
	all4, all6 := randomPrefixes4(numPerFamily), randomPrefixes6(numPerFamily)
	pfxs := append([]slowPrefixEntry[int](nil), all4[:deleteCut]...)
	pfxs = append(pfxs, all6[:deleteCut]...)
	toDelete := append([]slowPrefixEntry[int](nil), all4[deleteCut:]...)
	toDelete = append(toDelete, all6[deleteCut:]...)

	defer func() {
		if t.Failed() {
			for _, pfx := range pfxs {
				fmt.Printf("%q, ", pfx.pfx)
			}
			fmt.Println("")
			for _, pfx := range toDelete {
				fmt.Printf("%q, ", pfx.pfx)
			}
			fmt.Println("")
		}
	}()

	slow := slowPrefixTable[int]{pfxs}
	fast := Table[int]{}

	for _, pfx := range pfxs {
		fast.Insert(pfx.pfx, pfx.val)
	}

	for _, pfx := range toDelete {
		fast.Insert(pfx.pfx, pfx.val)
	}
	for _, pfx := range toDelete {
		fast.Delete(pfx.pfx)
	}

	seenVals4 := map[int]bool{}
	seenVals6 := map[int]bool{}
	for range numProbes {
		a := randomAddr()
		slowVal, slowOK := slow.get(a)
		fastVal, fastOK := fast.Get(a)
		if !getsEqual(slowVal, slowOK, fastVal, fastOK) {
			t.Fatalf("get(%q) = (%v, %v), want (%v, %v)", a, fastVal, fastOK, slowVal, slowOK)
		}
		if a.Is6() {
			seenVals6[fastVal] = true
		} else {
			seenVals4[fastVal] = true
		}
	}
	// Empirically, 10k probes into 5k v4 prefixes and 5k v6 prefixes results in
	// ~1k distinct values for v4 and ~300 for v6. distinct routes. This sanity
	// check that we didn't just return a single route for everything should be
	// very generous indeed.
	if cnt := len(seenVals4); cnt < 10 {
		t.Fatalf("saw %d distinct v4 route results, statistically expected ~1000", cnt)
	}
	if cnt := len(seenVals6); cnt < 10 {
		t.Fatalf("saw %d distinct v6 route results, statistically expected ~300", cnt)
	}
}

func TestDeleteShuffled(t *testing.T) {
	// The order in which you delete prefixes from a route table
	// should not matter, as long as you're deleting the same set of
	// routes. Verify that this is true, because ART does execute
	// vastly different code depending on the order of deletions, even
	// if the end result is identical.
	//
	// If you're here because this package's tests are slow and you
	// want to make them faster, please do not delete this test (or
	// any test, really). It may seem excessive to test this, but
	// these shuffle tests found a lot of very nasty edge cases during
	// development, and you _really_ don't want to be debugging a
	// faulty route table in production.
	t.Parallel()

	const (
		numPrefixes  = 10_000 // prefixes to insert (test deletes 50% of them)
		numPerFamily = numPrefixes / 2
		deleteCut    = numPerFamily / 2
		numProbes    = 10_000 // random addr lookups to do
	)

	// We have to do this little dance instead of just using allPrefixes,
	// because we want pfxs and toDelete to be non-overlapping sets.
	all4, all6 := randomPrefixes4(numPerFamily), randomPrefixes6(numPerFamily)
	pfxs := append([]slowPrefixEntry[int](nil), all4[:deleteCut]...)
	pfxs = append(pfxs, all6[:deleteCut]...)
	toDelete := append([]slowPrefixEntry[int](nil), all4[deleteCut:]...)
	toDelete = append(toDelete, all6[deleteCut:]...)

	rt := Table[int]{}
	for _, pfx := range pfxs {
		rt.Insert(pfx.pfx, pfx.val)
	}
	for _, pfx := range toDelete {
		rt.Insert(pfx.pfx, pfx.val)
	}
	for _, pfx := range toDelete {
		rt.Delete(pfx.pfx)
	}

	for range 10 {
		pfxs2 := append([]slowPrefixEntry[int](nil), pfxs...)
		toDelete2 := append([]slowPrefixEntry[int](nil), toDelete...)
		rand.Shuffle(len(toDelete2), func(i, j int) { toDelete2[i], toDelete2[j] = toDelete2[j], toDelete2[i] })
		rt2 := Table[int]{}
		for _, pfx := range pfxs2 {
			rt2.Insert(pfx.pfx, pfx.val)
		}
		for _, pfx := range toDelete2 {
			rt2.Insert(pfx.pfx, pfx.val)
		}
		for _, pfx := range toDelete2 {
			rt2.Delete(pfx.pfx)
		}

		// Diffing a deep tree of tables gives cmp.Diff a nervous breakdown, so
		// test for equivalence statistically with random probes instead.
		for range numProbes {
			a := randomAddr()
			val1, ok1 := rt.Get(a)
			val2, ok2 := rt2.Get(a)
			if !getsEqual(val1, ok1, val2, ok2) {
				t.Errorf("get(%q) = (%v, %v), want (%v, %v)", a, val2, ok2, val1, ok1)
			}
		}
	}
}

func TestDeleteIsReverseOfInsert(t *testing.T) {
	// Insert N prefixes, then delete those same prefixes in reverse
	// order. Each deletion should exactly undo the internal structure
	// changes that each insert did.
	const N = 100

	var tab Table[int]
	prefixes := randomPrefixes(N)

	defer func() {
		if t.Failed() {
			fmt.Printf("the prefixes that fail the test: %v\n", prefixes)
		}
	}()

	want := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		want = append(want, tab.debugSummary())
		tab.Insert(p.pfx, p.val)
	}

	for i := len(prefixes) - 1; i >= 0; i-- {
		tab.Delete(prefixes[i].pfx)
		if got := tab.debugSummary(); got != want[i] {
			t.Fatalf("after delete %d, mismatch:\n\n got: %s\n\nwant: %s", i, got, want[i])
		}
	}
}

type tableTest struct {
	// addr is an IP address string to look up in a route table.
	addr string
	// want is the expected >=0 value associated with the route, or -1
	// if we expect a lookup miss.
	want int
}

// checkRoutes verifies that the route lookups in tt return the
// expected results on tbl.
func checkRoutes(t *testing.T, tbl *Table[int], tt []tableTest) {
	t.Helper()
	for _, tc := range tt {
		v, ok := tbl.Get(netip.MustParseAddr(tc.addr))
		if !ok && tc.want != -1 {
			t.Errorf("lookup %q got (%v, %v), want (_, false)", tc.addr, v, ok)
		}
		if ok && v != tc.want {
			t.Errorf("lookup %q got (%v, %v), want (%v, true)", tc.addr, v, ok, tc.want)
		}
	}
}

// 100k routes for IPv6, at the current size of strideTable and strideEntry, is
// in the ballpark of 4GiB if you assume worst-case prefix distribution. Future
// optimizations will knock down the memory consumption by over an order of
// magnitude, so for now just skip the 100k benchmarks to stay well away of
// OOMs.
//
// TODO(go/bug/7781): reenable larger table tests once memory utilization is
// optimized.
var benchRouteCount = []int{10, 100, 1000, 10_000} //, 100_000}

// forFamilyAndCount runs the benchmark fn with different sets of
// routes.
//
// fn is called once for each combination of {addr_family, num_routes},
// where addr_family is ipv4 or ipv6, num_routes is the values in
// benchRouteCount.
func forFamilyAndCount(b *testing.B, fn func(b *testing.B, routes []slowPrefixEntry[int])) {
	for _, fam := range []string{"ipv4", "ipv6"} {
		rng := randomPrefixes4
		if fam == "ipv6" {
			rng = randomPrefixes6
		}
		b.Run(fam, func(b *testing.B) {
			for _, nroutes := range benchRouteCount {
				routes := rng(nroutes)
				b.Run(fmt.Sprint(nroutes), func(b *testing.B) {
					fn(b, routes)
				})
			}
		})
	}
}

func BenchmarkTableInsertion(b *testing.B) {
	forFamilyAndCount(b, func(b *testing.B, routes []slowPrefixEntry[int]) {
		b.StopTimer()
		b.ResetTimer()
		var startMem, endMem runtime.MemStats
		runtime.ReadMemStats(&startMem)
		b.StartTimer()
		for range b.N {
			var rt Table[int]
			for _, route := range routes {
				rt.Insert(route.pfx, route.val)
			}
		}
		b.StopTimer()
		runtime.ReadMemStats(&endMem)
		inserts := float64(b.N) * float64(len(routes))
		allocs := float64(endMem.Mallocs - startMem.Mallocs)
		bytes := float64(endMem.TotalAlloc - startMem.TotalAlloc)
		elapsed := float64(b.Elapsed().Nanoseconds())
		elapsedSec := b.Elapsed().Seconds()
		b.ReportMetric(elapsed/inserts, "ns/op")
		b.ReportMetric(inserts/elapsedSec, "routes/s")
		b.ReportMetric(roundFloat64(allocs/inserts), "avg-allocs/op")
		b.ReportMetric(roundFloat64(bytes/inserts), "avg-B/op")
	})
}

func BenchmarkTableDelete(b *testing.B) {
	forFamilyAndCount(b, func(b *testing.B, routes []slowPrefixEntry[int]) {
		// Collect memstats for one round of insertions, so we can remove it
		// from the total at the end and get only the deletion alloc count.
		insertAllocs, insertBytes := getMemCost(func() {
			var rt Table[int]
			for _, route := range routes {
				rt.Insert(route.pfx, route.val)
			}
		})
		insertAllocs *= float64(b.N)
		insertBytes *= float64(b.N)

		var t runningTimer
		allocs, bytes := getMemCost(func() {
			for range b.N {
				var rt Table[int]
				for _, route := range routes {
					rt.Insert(route.pfx, route.val)
				}
				t.Start()
				for _, route := range routes {
					rt.Delete(route.pfx)
				}
				t.Stop()
			}
		})
		inserts := float64(b.N) * float64(len(routes))
		allocs -= insertAllocs
		bytes -= insertBytes
		elapsed := float64(t.Elapsed().Nanoseconds())
		elapsedSec := t.Elapsed().Seconds()
		b.ReportMetric(elapsed/inserts, "ns/op")
		b.ReportMetric(inserts/elapsedSec, "routes/s")
		b.ReportMetric(roundFloat64(allocs/inserts), "avg-allocs/op")
		b.ReportMetric(roundFloat64(bytes/inserts), "avg-B/op")
	})
}

func BenchmarkTableGet(b *testing.B) {
	forFamilyAndCount(b, func(b *testing.B, routes []slowPrefixEntry[int]) {
		genAddr := randomAddr4
		if routes[0].pfx.Addr().Is6() {
			genAddr = randomAddr6
		}
		var rt Table[int]
		for _, route := range routes {
			rt.Insert(route.pfx, route.val)
		}
		addrAllocs, addrBytes := getMemCost(func() {
			// Have to run genAddr more than once, otherwise the reported
			// cost is 16 bytes - presumably due to some amortized costs in
			// the memory allocator? Either way, empirically 100 iterations
			// reliably reports the correct cost.
			for range 100 {
				_ = genAddr()
			}
		})
		addrAllocs /= 100
		addrBytes /= 100
		var t runningTimer
		allocs, bytes := getMemCost(func() {
			for range b.N {
				addr := genAddr()
				t.Start()
				writeSink, _ = rt.Get(addr)
				t.Stop()
			}
		})
		b.ReportAllocs() // Enables the output, but we report manually below
		allocs -= (addrAllocs * float64(b.N))
		bytes -= (addrBytes * float64(b.N))
		lookups := float64(b.N)
		elapsed := float64(t.Elapsed().Nanoseconds())
		elapsedSec := float64(t.Elapsed().Seconds())
		b.ReportMetric(elapsed/lookups, "ns/op")
		b.ReportMetric(lookups/elapsedSec, "addrs/s")
		b.ReportMetric(allocs/lookups, "allocs/op")
		b.ReportMetric(bytes/lookups, "B/op")

	})
}

// getMemCost runs fn 100 times and returns the number of allocations and bytes
// allocated by each call to fn.
//
// Note that if your fn allocates very little memory (less than ~16 bytes), you
// should make fn run its workload ~100 times and divide the results of
// getMemCost yourself. Otherwise, the byte count you get will be rounded up due
// to the memory allocator's bucketing granularity.
func getMemCost(fn func()) (allocs, bytes float64) {
	var start, end runtime.MemStats
	runtime.ReadMemStats(&start)
	fn()
	runtime.ReadMemStats(&end)
	return float64(end.Mallocs - start.Mallocs), float64(end.TotalAlloc - start.TotalAlloc)
}

// runningTimer is a timer that keeps track of the cumulative time it's spent
// running since creation. A newly created runningTimer is stopped.
//
// This timer exists because some of our benchmarks have to interleave costly
// ancillary logic in each benchmark iteration, rather than being able to
// front-load all the work before a single b.ResetTimer().
//
// As it turns out, b.StartTimer() and b.StopTimer() are expensive function
// calls, because they do costly memory allocation accounting on every call.
// Starting and stopping the benchmark timer in every b.N loop iteration slows
// the benchmarks down by orders of magnitude.
//
// So, rather than rely on testing.B's timing facility, we use this very
// lightweight timer combined with getMemCost to do our own accounting more
// efficiently.
type runningTimer struct {
	cumulative time.Duration
	start      time.Time
}

func (t *runningTimer) Start() {
	t.Stop()
	t.start = time.Now()
}

func (t *runningTimer) Stop() {
	if t.start.IsZero() {
		return
	}
	t.cumulative += time.Since(t.start)
	t.start = time.Time{}
}

func (t *runningTimer) Elapsed() time.Duration {
	return t.cumulative
}

func checkSize(t *testing.T, tbl *Table[int], want int) {
	t.Helper()
	if got := tbl.numStrides(); got != want {
		t.Errorf("wrong table size, got %d strides want %d", got, want)
	}
}

func (t *Table[T]) numStrides() int {
	seen := map[*strideTable[T]]bool{}
	return t.numStridesRec(seen, &t.v4) + t.numStridesRec(seen, &t.v6)
}

func (t *Table[T]) numStridesRec(seen map[*strideTable[T]]bool, st *strideTable[T]) int {
	ret := 1
	if st.childRefs == 0 {
		return ret
	}
	for _, c := range st.children {
		if c == nil || seen[c] {
			continue
		}
		seen[c] = true
		ret += t.numStridesRec(seen, c)
	}
	return ret
}

// slowPrefixTable is a routing table implemented as a set of prefixes that are
// explicitly scanned in full for every route lookup. It is very slow, but also
// reasonably easy to verify by inspection, and so a good correctness reference
// for Table.
type slowPrefixTable[T any] struct {
	prefixes []slowPrefixEntry[T]
}

type slowPrefixEntry[T any] struct {
	pfx netip.Prefix
	val T
}

func (t *slowPrefixTable[T]) insert(pfx netip.Prefix, val T) {
	pfx = pfx.Masked()
	for i, ent := range t.prefixes {
		if ent.pfx == pfx {
			t.prefixes[i].val = val
			return
		}
	}
	t.prefixes = append(t.prefixes, slowPrefixEntry[T]{pfx, val})
}

func (t *slowPrefixTable[T]) get(addr netip.Addr) (ret T, ok bool) {
	bestLen := -1

	for _, pfx := range t.prefixes {
		if pfx.pfx.Contains(addr) && pfx.pfx.Bits() > bestLen {
			ret = pfx.val
			bestLen = pfx.pfx.Bits()
		}
	}
	return ret, bestLen != -1
}

// randomPrefixes returns n randomly generated prefixes and associated values,
// distributed equally between IPv4 and IPv6.
func randomPrefixes(n int) []slowPrefixEntry[int] {
	pfxs := randomPrefixes4(n / 2)
	pfxs = append(pfxs, randomPrefixes6(n-len(pfxs))...)
	return pfxs
}

// randomPrefixes4 returns n randomly generated IPv4 prefixes and associated values.
func randomPrefixes4(n int) []slowPrefixEntry[int] {
	pfxs := map[netip.Prefix]bool{}

	for len(pfxs) < n {
		len := rand.Intn(33)
		pfx, err := randomAddr4().Prefix(len)
		if err != nil {
			panic(err)
		}
		pfxs[pfx] = true
	}

	ret := make([]slowPrefixEntry[int], 0, len(pfxs))
	for pfx := range pfxs {
		ret = append(ret, slowPrefixEntry[int]{pfx, rand.Int()})
	}

	return ret
}

// randomPrefixes6 returns n randomly generated IPv4 prefixes and associated values.
func randomPrefixes6(n int) []slowPrefixEntry[int] {
	pfxs := map[netip.Prefix]bool{}

	for len(pfxs) < n {
		len := rand.Intn(129)
		pfx, err := randomAddr6().Prefix(len)
		if err != nil {
			panic(err)
		}
		pfxs[pfx] = true
	}

	ret := make([]slowPrefixEntry[int], 0, len(pfxs))
	for pfx := range pfxs {
		ret = append(ret, slowPrefixEntry[int]{pfx, rand.Int()})
	}

	return ret
}

// randomAddr returns a randomly generated IP address.
func randomAddr() netip.Addr {
	if rand.Intn(2) == 1 {
		return randomAddr6()
	} else {
		return randomAddr4()
	}
}

// randomAddr4 returns a randomly generated IPv4 address.
func randomAddr4() netip.Addr {
	var b [4]byte
	if _, err := crand.Read(b[:]); err != nil {
		panic(err)
	}
	return netip.AddrFrom4(b)
}

// randomAddr6 returns a randomly generated IPv6 address.
func randomAddr6() netip.Addr {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		panic(err)
	}
	return netip.AddrFrom16(b)
}

// roundFloat64 rounds f to 2 decimal places, for display.
//
// It round-trips through a float->string->float conversion, so should not be
// used in a performance critical setting.
func roundFloat64(f float64) float64 {
	s := fmt.Sprintf("%.2f", f)
	ret, err := strconv.ParseFloat(s, 64)
	if err != nil {
		panic(err)
	}
	return ret
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package art

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestInversePrefix(t *testing.T) {
	t.Parallel()
	for i := range 256 {
		for len := 0; len < 9; len++ {
			addr := i & (0xFF << (8 - len))
			idx := prefixIndex(uint8(addr), len)
			addr2, len2 := inversePrefixIndex(idx)
			if addr2 != uint8(addr) || len2 != len {
				t.Errorf("inverse(index(%d/%d)) != %d/%d", addr, len, addr2, len2)
			}
		}
	}
}

func TestHostIndex(t *testing.T) {
	t.Parallel()
	for i := range 256 {
		got := hostIndex(uint8(i))
		want := prefixIndex(uint8(i), 8)
		if got != want {
			t.Errorf("hostIndex(%d) = %d, want %d", i, got, want)
		}
	}
}

func TestStrideTableInsert(t *testing.T) {
	t.Parallel()
	// Verify that strideTable's lookup results after a bunch of inserts exactly
	// match those of a naive implementation that just scans all prefixes on
	// every lookup. The naive implementation is very slow, but its behavior is
	// easy to verify by inspection.

	pfxs := shufflePrefixes(allPrefixes())[:100]
	slow := slowTable[int]{pfxs}
	fast := strideTable[int]{}

	if debugStrideInsert {
		t.Logf("slow table:\n%s", slow.String())
	}

	for _, pfx := range pfxs {
		fast.insert(pfx.addr, pfx.len, pfx.val)
		if debugStrideInsert {
			t.Logf("after insert %d/%d:\n%s", pfx.addr, pfx.len, fast.tableDebugString())
		}
	}

	for i := range 256 {
		addr := uint8(i)
		slowVal, slowOK := slow.get(addr)
		fastVal, fastOK := fast.get(addr)
		if !getsEqual(fastVal, fastOK, slowVal, slowOK) {
			t.Fatalf("strideTable.get(%d) = (%v, %v), want (%v, %v)", addr, fastVal, fastOK, slowVal, slowOK)
		}
	}
}

func TestStrideTableInsertShuffled(t *testing.T) {
	t.Parallel()
	// The order in which routes are inserted into a route table does not
	// influence the final shape of the table, as long as the same set of
	// prefixes is being inserted. This test verifies that strideTable behaves
	// this way.
	//
	// In addition to the basic shuffle test, we also check that this behavior
	// is maintained if all inserted routes have the same value pointer. This
	// shouldn't matter (the strideTable still needs to correctly account for
	// each inserted route, regardless of associated value), but during initial
	// development a subtle bug made the table corrupt itself in that setup, so
	// this test includes a regression test for that.

	routes := shufflePrefixes(allPrefixes())[:100]

	zero := 0
	rt := strideTable[int]{}
	// strideTable has a value interface, but internally has to keep
	// track of distinct routes even if they all have the same
	// value. rtZero uses the same value for all routes, and expects
	// correct behavior.
	rtZero := strideTable[int]{}
	for _, route := range routes {
		rt.insert(route.addr, route.len, route.val)
		rtZero.insert(route.addr, route.len, zero)
	}

	// Order of insertion should not affect the final shape of the stride table.
	routes2 := append([]slowEntry[int](nil), routes...) // dup so we can print both slices on fail
	for range 100 {
		rand.Shuffle(len(routes2), func(i, j int) { routes2[i], routes2[j] = routes2[j], routes2[i] })
		rt2 := strideTable[int]{}
		for _, route := range routes2 {
			rt2.insert(route.addr, route.len, route.val)
		}
		if diff := cmp.Diff(rt.tableDebugString(), rt2.tableDebugString()); diff != "" {
			t.Errorf("tables ended up different with different insertion order (-got+want):\n%s\n\nOrder 1: %v\nOrder 2: %v", diff, formatSlowEntriesShort(routes), formatSlowEntriesShort(routes2))
		}

		rtZero2 := strideTable[int]{}
		for _, route := range routes2 {
			rtZero2.insert(route.addr, route.len, zero)
		}
		if diff := cmp.Diff(rtZero.tableDebugString(), rtZero2.tableDebugString(), cmpDiffOpts...); diff != "" {
			t.Errorf("tables with identical vals ended up different with different insertion order (-got+want):\n%s\n\nOrder 1: %v\nOrder 2: %v", diff, formatSlowEntriesShort(routes), formatSlowEntriesShort(routes2))
		}
	}
}

func TestStrideTableDelete(t *testing.T) {
	t.Parallel()
	// Compare route deletion to our reference slowTable.
	pfxs := shufflePrefixes(allPrefixes())[:100]
	slow := slowTable[int]{pfxs}
	fast := strideTable[int]{}

	if debugStrideDelete {
		t.Logf("slow table:\n%s", slow.String())
	}

	for _, pfx := range pfxs {
		fast.insert(pfx.addr, pfx.len, pfx.val)
		if debugStrideDelete {
			t.Logf("after insert %d/%d:\n%s", pfx.addr, pfx.len, fast.tableDebugString())
		}
	}

	toDelete := pfxs[:50]
	for _, pfx := range toDelete {
		slow.delete(pfx.addr, pfx.len)
		fast.delete(pfx.addr, pfx.len)
	}

	// Sanity check that slowTable seems to have done the right thing.
	if cnt := len(slow.prefixes); cnt != 50 {
		t.Fatalf("slowTable has %d entries after deletes, want 50", cnt)
	}

	for i := range 256 {
		addr := uint8(i)
		slowVal, slowOK := slow.get(addr)
		fastVal, fastOK := fast.get(addr)
		if !getsEqual(fastVal, fastOK, slowVal, slowOK) {
			t.Fatalf("strideTable.get(%d) = (%v, %v), want (%v, %v)", addr, fastVal, fastOK, slowVal, slowOK)
		}
	}
}

func TestStrideTableDeleteShuffle(t *testing.T) {
	t.Parallel()
	// Same as TestStrideTableInsertShuffle, the order in which prefixes are
	// deleted should not impact the final shape of the route table.

	routes := shufflePrefixes(allPrefixes())[:100]
	toDelete := routes[:50]

	zero := 0
	rt := strideTable[int]{}
	// strideTable has a value interface, but internally has to keep
	// track of distinct routes even if they all have the same
	// value. rtZero uses the same value for all routes, and expects
	// correct behavior.
	rtZero := strideTable[int]{}
	for _, route := range routes {
		rt.insert(route.addr, route.len, route.val)
		rtZero.insert(route.addr, route.len, zero)
	}
	for _, route := range toDelete {
		rt.delete(route.addr, route.len)
		rtZero.delete(route.addr, route.len)
	}

	// Order of deletion should not affect the final shape of the stride table.
	toDelete2 := append([]slowEntry[int](nil), toDelete...) // dup so we can print both slices on fail
	for range 100 {
		rand.Shuffle(len(toDelete2), func(i, j int) { toDelete2[i], toDelete2[j] = toDelete2[j], toDelete2[i] })
		rt2 := strideTable[int]{}
		for _, route := range routes {
			rt2.insert(route.addr, route.len, route.val)
		}
		for _, route := range toDelete2 {
			rt2.delete(route.addr, route.len)
		}
		if diff := cmp.Diff(rt.tableDebugString(), rt2.tableDebugString(), cmpDiffOpts...); diff != "" {
			t.Errorf("tables ended up different with different deletion order (-got+want):\n%s\n\nOrder 1: %v\nOrder 2: %v", diff, formatSlowEntriesShort(toDelete), formatSlowEntriesShort(toDelete2))
		}

		rtZero2 := strideTable[int]{}
		for _, route := range routes {
			rtZero2.insert(route.addr, route.len, zero)
		}
		for _, route := range toDelete2 {
			rtZero2.delete(route.addr, route.len)
		}
		if diff := cmp.Diff(rtZero.tableDebugString(), rtZero2.tableDebugString(), cmpDiffOpts...); diff != "" {
			t.Errorf("tables with identical vals ended up different with different deletion order (-got+want):\n%s\n\nOrder 1: %v\nOrder 2: %v", diff, formatSlowEntriesShort(toDelete), formatSlowEntriesShort(toDelete2))
		}
	}
}

var strideRouteCount = []int{10, 50, 100, 200}

// forCountAndOrdering runs the benchmark fn with different sets of routes.
//
// fn is called once for each combination of {num_routes, order}, where
// num_routes is the values in strideRouteCount, and order is the order of the
// routes in the list: random, largest prefix first (/0 to /8), and smallest
// prefix first (/8 to /0).
func forStrideCountAndOrdering(b *testing.B, fn func(b *testing.B, routes []slowEntry[int])) {
	routes := shufflePrefixes(allPrefixes())
	for _, nroutes := range strideRouteCount {
		b.Run(fmt.Sprint(nroutes), func(b *testing.B) {
			runAndRecord := func(b *testing.B) {
				b.ReportAllocs()
				var startMem, endMem runtime.MemStats
				runtime.ReadMemStats(&startMem)
				fn(b, routes)
				runtime.ReadMemStats(&endMem)
				ops := float64(b.N) * float64(len(routes))
				allocs := float64(endMem.Mallocs - startMem.Mallocs)
				bytes := float64(endMem.TotalAlloc - startMem.TotalAlloc)
				b.ReportMetric(roundFloat64(allocs/ops), "allocs/op")
				b.ReportMetric(roundFloat64(bytes/ops), "B/op")
			}

			routes := append([]slowEntry[int](nil), routes[:nroutes]...)
			b.Run("random_order", runAndRecord)
			sort.Slice(routes, func(i, j int) bool {
				if routes[i].len < routes[j].len {
					return true
				}
				return routes[i].addr < routes[j].addr
			})
			b.Run("largest_first", runAndRecord)
			sort.Slice(routes, func(i, j int) bool {
				if routes[j].len < routes[i].len {
					return true
				}
				return routes[j].addr < routes[i].addr
			})
			b.Run("smallest_first", runAndRecord)
		})
	}
}

func BenchmarkStrideTableInsertion(b *testing.B) {
	forStrideCountAndOrdering(b, func(b *testing.B, routes []slowEntry[int]) {
		val := 0
		for range b.N {
			var rt strideTable[int]
			for _, route := range routes {
				rt.insert(route.addr, route.len, val)
			}
		}
		inserts := float64(b.N) * float64(len(routes))
		elapsed := float64(b.Elapsed().Nanoseconds())
		elapsedSec := b.Elapsed().Seconds()
		b.ReportMetric(elapsed/inserts, "ns/op")
		b.ReportMetric(inserts/elapsedSec, "routes/s")
	})
}

func BenchmarkStrideTableDeletion(b *testing.B) {
	forStrideCountAndOrdering(b, func(b *testing.B, routes []slowEntry[int]) {
		val := 0
		var rt strideTable[int]
		for _, route := range routes {
			rt.insert(route.addr, route.len, val)
		}

		b.ResetTimer()
		for range b.N {
			rt2 := rt
			for _, route := range routes {
				rt2.delete(route.addr, route.len)
			}
		}
		deletes := float64(b.N) * float64(len(routes))
		elapsed := float64(b.Elapsed().Nanoseconds())
		elapsedSec := b.Elapsed().Seconds()
		b.ReportMetric(elapsed/deletes, "ns/op")
		b.ReportMetric(deletes/elapsedSec, "routes/s")
	})
}

var writeSink int

func BenchmarkStrideTableGet(b *testing.B) {
	// No need to forCountAndOrdering here, route lookup time is independent of
	// the route count.
	routes := shufflePrefixes(allPrefixes())[:100]
	var rt strideTable[int]
	for _, route := range routes {
		rt.insert(route.addr, route.len, route.val)
	}

	b.ResetTimer()
	for i := range b.N {
		writeSink, _ = rt.get(uint8(i))
	}
	gets := float64(b.N)
	elapsedSec := b.Elapsed().Seconds()
	b.ReportMetric(gets/elapsedSec, "routes/s")
}

// slowTable is an 8-bit routing table implemented as a set of prefixes that are
// explicitly scanned in full for every route lookup. It is very slow, but also
// reasonably easy to verify by inspection, and so a good comparison target for
// strideTable.
type slowTable[T any] struct {
	prefixes []slowEntry[T]
}

type slowEntry[T any] struct {
	addr uint8
	len  int
	val  T
}

func (t *slowTable[T]) String() string {
	pfxs := append([]slowEntry[T](nil), t.prefixes...)
	sort.Slice(pfxs, func(i, j int) bool {
		if pfxs[i].len != pfxs[j].len {
			return pfxs[i].len < pfxs[j].len
		}
		return pfxs[i].addr < pfxs[j].addr
	})
	var ret bytes.Buffer
	for _, pfx := range pfxs {
		fmt.Fprintf(&ret, "%3d/%d (%08b/%08b) = %v\n", pfx.addr, pfx.len, pfx.addr, pfxMask(pfx.len), pfx.val)
	}
	return ret.String()
}

func (t *slowTable[T]) delete(addr uint8, prefixLen int) {
	pfx := make([]slowEntry[T], 0, len(t.prefixes))
	for _, e := range t.prefixes {
		if e.addr == addr && e.len == prefixLen {
			continue
		}
		pfx = append(pfx, e)
	}
	t.prefixes = pfx
}

func (t *slowTable[T]) get(addr uint8) (ret T, ok bool) {
	var curLen = -1
	for _, e := range t.prefixes {
		if addr&pfxMask(e.len) == e.addr && e.len >= curLen {
			ret = e.val
			curLen = e.len
		}
	}
	return ret, curLen != -1
}

func pfxMask(pfxLen int) uint8 {
	return 0xFF << (8 - pfxLen)
}

func allPrefixes() []slowEntry[int] {
	ret := make([]slowEntry[int], 0, lastHostIndex)
	for i := 1; i < lastHostIndex+1; i++ {
		a, ln := inversePrefixIndex(i)
		ret = append(ret, slowEntry[int]{a, ln, i})
	}
	return ret
}

func shufflePrefixes(pfxs []slowEntry[int]) []slowEntry[int] {
	rand.Shuffle(len(pfxs), func(i, j int) { pfxs[i], pfxs[j] = pfxs[j], pfxs[i] })
	return pfxs
}

func formatSlowEntriesShort[T any](ents []slowEntry[T]) string {
	var ret []string
	for _, ent := range ents {
		ret = append(ret, fmt.Sprintf("%d/%d", ent.addr, ent.len))
	}
	return "[" + strings.Join(ret, " ") + "]"
}

var cmpDiffOpts = []cmp.Option{
	cmp.Comparer(func(a, b netip.Prefix) bool { return a == b }),
}

func getsEqual[T comparable](a T, aOK bool, b T, bOK bool) bool {
	if !aOK && !bOK {
		return true
	}
	if aOK != bOK {
		return false
	}
	return a == b
}

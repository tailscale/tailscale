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

	"tailscale.com/types/ptr"
)

func TestInsert(t *testing.T) {
	t.Parallel()
	pfxs := randomPrefixes(10_000)

	slow := slowPrefixTable[int]{pfxs}
	fast := Table[int]{}

	for _, pfx := range pfxs {
		fast.Insert(pfx.pfx, pfx.val)
	}

	t.Logf(fast.debugSummary())

	seenVals4 := map[*int]bool{}
	seenVals6 := map[*int]bool{}
	for i := 0; i < 10_000; i++ {
		a := randomAddr()
		slowVal := slow.get(a)
		fastVal := fast.Get(a)
		if a.Is6() {
			seenVals6[fastVal] = true
		} else {
			seenVals4[fastVal] = true
		}
		if slowVal != fastVal {
			t.Errorf("get(%q) = %p, want %p", a, fastVal, slowVal)
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
	t.Parallel()
	pfxs := randomPrefixes(10_000)

	rt := Table[int]{}
	for _, pfx := range pfxs {
		rt.Insert(pfx.pfx, pfx.val)
	}

	for i := 0; i < 10; i++ {
		pfxs2 := append([]slowPrefixEntry[int](nil), pfxs...)
		rand.Shuffle(len(pfxs2), func(i, j int) { pfxs2[i], pfxs2[j] = pfxs2[j], pfxs2[i] })
		rt2 := Table[int]{}
		for _, pfx := range pfxs2 {
			rt2.Insert(pfx.pfx, pfx.val)
		}

		// Diffing a deep tree of tables gives cmp.Diff a nervous breakdown, so
		// test for equivalence statistically with random probes instead.
		for i := 0; i < 10_000; i++ {
			a := randomAddr()
			val1 := rt.Get(a)
			val2 := rt2.Get(a)
			if (val1 == nil && val2 != nil) || (val1 != nil && val2 == nil) || (*val1 != *val2) {
				t.Errorf("get(%q) = %s, want %s", a, printIntPtr(val2), printIntPtr(val1))
			}
		}
	}
}

func TestDelete(t *testing.T) {
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

	seenVals4 := map[*int]bool{}
	seenVals6 := map[*int]bool{}
	for i := 0; i < numProbes; i++ {
		a := randomAddr()
		slowVal := slow.get(a)
		fastVal := fast.Get(a)
		if a.Is6() {
			seenVals6[fastVal] = true
		} else {
			seenVals4[fastVal] = true
		}
		if slowVal != fastVal {
			t.Fatalf("get(%q) = %p, want %p", a, fastVal, slowVal)
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

	for i := 0; i < 10; i++ {
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
		for i := 0; i < numProbes; i++ {
			a := randomAddr()
			val1 := rt.Get(a)
			val2 := rt2.Get(a)
			if val1 == nil && val2 == nil {
				continue
			}
			if (val1 == nil && val2 != nil) || (val1 != nil && val2 == nil) || (*val1 != *val2) {
				t.Errorf("get(%q) = %s, want %s", a, printIntPtr(val2), printIntPtr(val1))
			}
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
		for i := 0; i < b.N; i++ {
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
			for i := 0; i < b.N; i++ {
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

var addrSink netip.Addr

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
			for i := 0; i < 100; i++ {
				_ = genAddr()
			}
		})
		addrAllocs /= 100
		addrBytes /= 100
		var t runningTimer
		allocs, bytes := getMemCost(func() {
			for i := 0; i < b.N; i++ {
				addr := genAddr()
				t.Start()
				writeSink = rt.Get(addr)
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

// slowPrefixTable is a routing table implemented as a set of prefixes that are
// explicitly scanned in full for every route lookup. It is very slow, but also
// reasonably easy to verify by inspection, and so a good correctness reference
// for Table.
type slowPrefixTable[T any] struct {
	prefixes []slowPrefixEntry[T]
}

type slowPrefixEntry[T any] struct {
	pfx netip.Prefix
	val *T
}

func (t *slowPrefixTable[T]) delete(pfx netip.Prefix) {
	ret := make([]slowPrefixEntry[T], 0, len(t.prefixes))
	for _, ent := range t.prefixes {
		if ent.pfx == pfx {
			continue
		}
		ret = append(ret, ent)
	}
	t.prefixes = ret
}

func (t *slowPrefixTable[T]) insert(pfx netip.Prefix, val *T) {
	for _, ent := range t.prefixes {
		if ent.pfx == pfx {
			ent.val = val
			return
		}
	}
	t.prefixes = append(t.prefixes, slowPrefixEntry[T]{pfx, val})
}

func (t *slowPrefixTable[T]) get(addr netip.Addr) *T {
	var (
		ret     *T
		bestLen = -1
	)

	for _, pfx := range t.prefixes {
		if pfx.pfx.Contains(addr) && pfx.pfx.Bits() > bestLen {
			ret = pfx.val
			bestLen = pfx.pfx.Bits()
		}
	}
	return ret
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
		ret = append(ret, slowPrefixEntry[int]{pfx, ptr.To(rand.Int())})
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
		ret = append(ret, slowPrefixEntry[int]{pfx, ptr.To(rand.Int())})
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

// printIntPtr returns *v as a string, or the literal "<nil>" if v is nil.
func printIntPtr(v *int) string {
	if v == nil {
		return "<nil>"
	}
	return fmt.Sprint(*v)
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

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package varz

import (
	"io"
	"math"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
)

// runtimeMetricSpec describes one Go runtime/metrics metric that
// [Handler] exports in Prometheus format.
type runtimeMetricSpec struct {
	// name is the runtime/metrics name, such as "/gc/heap/allocs:bytes".
	name string

	// typ is the Prometheus type: "gauge", "counter", or "histogram".
	// Counters get a "_total" suffix, as in the Prometheus naming
	// conventions.
	typ string

	// buckets says how a histogram's runtime buckets map to Prometheus
	// buckets. It is required for histograms and ignored otherwise.
	buckets histBuckets

	// hidden means the metric is read (because it backs one of the
	// legacy memstats_* metrics) but is not exported under its own
	// go_runtime_ name.
	hidden bool
}

// histBuckets says how the runtime's lower-bound-inclusive buckets
// [lo, hi) of a histogram become Prometheus's upper-bound-inclusive
// le buckets.
type histBuckets uint8

const (
	// histTime is for the runtime's time histograms, which have
	// hundreds of buckets. They are reduced as described at
	// [runtimeHistMinBucket], and a runtime bucket [lo, hi) becomes
	// le=hi, which is only wrong for a value exactly equal to hi.
	histTime histBuckets = iota + 1

	// histPowersOfTwo is for histograms whose observed values are all
	// exactly equal to bucket lower bounds, such as goroutine stack
	// sizes. A runtime bucket [lo, hi) becomes le=lo, so the labels
	// name the values they count, and the runtime's final catch-all
	// bucket is folded into +Inf.
	histPowersOfTwo

	// histInts is for histograms of small integer values, such as
	// counts of GC cycles. A runtime bucket [lo, hi) becomes le=hi-1,
	// which is exact for integers.
	histInts
)

// runtimeMetricSpecs is the set of Go runtime/metrics metrics that
// [Handler] reads. Everything here is cheap for the runtime to read: no
// metric in this list stops the world or walks the heap or the
// goroutine list.
//
// The list is deliberately short. The hidden entries only back the
// legacy memstats_* metrics. The rest are either specific to the
// Tailscale fork of Go or have no runtime.MemStats equivalent and earn
// their place on a dashboard.
//
// Names that the running toolchain does not know (such as the
// /tailscale/ metrics when not built with the fork) are dropped on
// first use, so it is fine for this list to be a superset of what
// exists.
//
// Go's Cumulative metrics are declared as counters here and the rest
// as gauges; TestRuntimeMetricSpecs checks that against the
// runtime's own descriptions.
var runtimeMetricSpecs = []runtimeMetricSpec{
	// These back the memstats_* metrics; see memstatsIndexes.
	{name: "/memory/classes/heap/objects:bytes", typ: "gauge", hidden: true},
	{name: "/gc/heap/allocs:bytes", typ: "counter", hidden: true},
	{name: "/memory/classes/total:bytes", typ: "gauge", hidden: true},
	{name: "/gc/heap/allocs:objects", typ: "counter", hidden: true},
	{name: "/gc/heap/frees:objects", typ: "counter", hidden: true},
	{name: "/gc/heap/tiny/allocs:objects", typ: "counter", hidden: true},
	{name: "/gc/cycles/total:gc-cycles", typ: "counter", hidden: true},
	{name: "/cpu/classes/gc/mark/idle:cpu-seconds", typ: "counter", hidden: true},

	// GC CPU time as counters, so that rate() over a window works.
	// memstats_gc_cpu_fraction, derived from these two (less the
	// hidden idle mark time above), is a lifetime average and cannot
	// show a recent change.
	{name: "/cpu/classes/gc/total:cpu-seconds", typ: "counter"},
	{name: "/cpu/classes/total:cpu-seconds", typ: "counter"},

	// Live heap after the last GC. Unlike memstats_heap_alloc it
	// excludes garbage not yet swept, so it is the number to compare
	// against GOMEMLIMIT or a container memory limit.
	{name: "/gc/heap/live:bytes", typ: "gauge"},

	// How long runnable goroutines wait to be scheduled, and how long
	// GC stop-the-world pauses take. Neither is visible any other way.
	{name: "/sched/latencies:seconds", typ: "histogram", buckets: histTime},
	{name: "/sched/pauses/total/gc:seconds", typ: "histogram", buckets: histTime},

	// OS threads owned by the runtime, for spotting thread leaks from
	// blocking syscalls or cgo.
	{name: "/sched/threads/total:threads", typ: "gauge"},

	// Time spent blocked on mutexes. cmd/derper used to export this
	// itself as go_sync_mutex_wait_seconds.
	{name: "/sync/mutex/wait/total:seconds", typ: "counter"},

	// The /tailscale/ metrics exist only in the Tailscale fork of Go
	// (github.com/tailscale/go), used when building with the
	// tailscale_go build tag.
	{name: "/tailscale/sched/goroutines-by-stack-size:bytes", typ: "histogram", buckets: histPowersOfTwo},
	{name: "/tailscale/sched/stacks/copied:bytes", typ: "counter"},
	{name: "/tailscale/sched/stacks/growths:events", typ: "counter"},
	{name: "/tailscale/sched/stacks/shrinks:events", typ: "counter"},
	{name: "/tailscale/sched/timers/tracked:timers", typ: "gauge"},
	{name: "/tailscale/sched/timers/zombies/chan:timers", typ: "gauge"},
	{name: "/tailscale/sched/timers/zombies/func:timers", typ: "gauge"},
	{name: "/tailscale/sched/timers/zombies/func/created:timers", typ: "counter"},
	{name: "/tailscale/sched/timers/zombies/func/removed:timers", typ: "counter"},
	{name: "/tailscale/sched/timers/zombies/func/lifetime:gc-cycles", typ: "histogram", buckets: histInts},
	{name: "/tailscale/sched/timers/zombies:timers", typ: "gauge"},
}

// runtimeMetricPrefix is the namespace prefix of exported runtime
// metrics. It is deliberately not "go_", which is the namespace used
// by the Prometheus Go client's collector; binaries that also use that
// client (see tailscale.com/tsweb/promvarz) would otherwise export
// some series twice, and Prometheus rejects a scrape containing
// duplicate series.
const runtimeMetricPrefix = "go_runtime_"

// runtimeMetricPromName converts a runtime/metrics name such as
// "/gc/heap/allocs:bytes" to a Prometheus metric name such as
// "go_runtime_gc_heap_allocs_bytes_total". The conversion follows the
// same rules as the Prometheus Go client's collector, other than the
// namespace: the path becomes the name with slashes and dashes
// replaced by underscores, the unit is appended, and counters get a
// "_total" suffix.
func runtimeMetricPromName(name, typ string) string {
	path, unit, _ := strings.Cut(strings.TrimPrefix(name, "/"), ":")
	r := strings.NewReplacer("/", "_", "-", "_")
	unit = strings.ReplaceAll(unit, "/", "_per_")
	unit = strings.ReplaceAll(unit, "*", "_")
	s := runtimeMetricPrefix + r.Replace(path) + "_" + r.Replace(unit)
	if typ == "counter" {
		s += "_total"
	}
	return s
}

// Time histograms from the runtime have hundreds of buckets, four per
// power of two from 256ns (finer below that) to about a day. That is
// far too many series for Prometheus, so they are reduced to one
// bucket per factor of runtimeHistBucketFactor starting at
// runtimeHistMinBucket, and everything above runtimeHistMaxBucket is
// folded into the +Inf bucket. Because the runtime's bucket boundaries
// are at powers of two times small integers, a factor of 4 starting at
// 256ns lands exactly on runtime boundaries, so the reduction only
// merges runtime buckets and never splits one.
const (
	runtimeHistMinBucket    = 256e-9 // seconds
	runtimeHistMaxBucket    = 1.0    // seconds
	runtimeHistBucketFactor = 4
)

// runtimeHistLayout describes how a runtime histogram's buckets are
// merged into the exported Prometheus buckets. It is computed once per
// metric from the runtime's bucket boundaries, which never change.
type runtimeHistLayout struct {
	// lines[i] is the exported line prefix for output bucket i, up to
	// and including the space before the value:
	// `name_bucket{le="0.001"} `. The last entry is the +Inf bucket.
	lines [][]byte

	// ends[i] is the number of leading runtime bucket counts summed
	// into output bucket i, which is cumulative like Prometheus
	// buckets. The last entry, for +Inf, is the total number of
	// runtime buckets.
	ends []int
}

// newRuntimeHistLayout computes the export layout for a runtime
// histogram with the given bucket boundaries (as in
// [metrics.Float64Histogram.Buckets], so the runtime bucket i counts
// values in [buckets[i], buckets[i+1])).
func newRuntimeHistLayout(promName string, buckets []float64, kind histBuckets) *runtimeHistLayout {
	numCounts := len(buckets) - 1
	lay := new(runtimeHistLayout)
	addBucket := func(le float64, end int) {
		line := append([]byte(promName), `_bucket{le="`...)
		if math.IsInf(le, 1) {
			line = append(line, "+Inf"...)
		} else {
			line = strconv.AppendFloat(line, le, 'g', -1, 64)
		}
		line = append(line, `"} `...)
		lay.lines = append(lay.lines, line)
		lay.ends = append(lay.ends, end)
	}
	switch kind {
	case histPowersOfTwo:
		// All but the final catch-all runtime bucket, each labeled
		// with its lower bound.
		for i := 0; i < numCounts-1; i++ {
			addBucket(buckets[i], i+1)
		}
	case histInts:
		// All but the final catch-all runtime bucket, each labeled
		// with the largest integer it contains.
		for i := 1; i < numCounts; i++ {
			addBucket(buckets[i]-1, i)
		}
	case histTime:
		last := 0.0
		for i := 1; i < numCounts; i++ {
			hi := buckets[i]
			if math.IsInf(hi, 0) || hi < runtimeHistMinBucket {
				continue
			}
			if last > runtimeHistMaxBucket {
				break
			}
			if last == 0 || hi >= last*runtimeHistBucketFactor {
				addBucket(hi, i)
				last = hi
			}
		}
	}
	addBucket(math.Inf(1), numCounts)
	return lay
}

// runtimeMetricState is a metric being exported, alongside its
// [metrics.Sample] in [runtimeMetricsExporter.samples].
type runtimeMetricState struct {
	spec runtimeMetricSpec

	// typeLine is the "# TYPE name type\n" line.
	typeLine []byte

	// valuePrefix is "name " for scalar metrics, or nil for histograms.
	valuePrefix []byte

	// countPrefix is "name_count " for histograms, or nil otherwise.
	countPrefix []byte

	// hist is the bucket layout for histograms, or nil otherwise.
	hist *runtimeHistLayout
}

// runtimeMetricsExporter reads a fixed set of Go runtime/metrics and
// writes them in Prometheus format. There is one, [runtimeMetrics],
// and it keeps its sample slice across reads so that the runtime can
// reuse histogram buffers and a steady-state scrape does not allocate.
type runtimeMetricsExporter struct {
	mu      sync.Mutex
	inited  bool
	samples []metrics.Sample      // reused across reads; parallel to states
	states  []*runtimeMetricState // parallel to samples

	// Indexes into samples of the metrics backing the legacy
	// memstats_* names, or -1 if the runtime lacks them.
	memstatsIdx memstatsIndexes
}

// memstatsIndexes holds indexes into [runtimeMetricsExporter.samples]
// for the runtime/metrics equivalents of the runtime.MemStats fields
// that varz has exported as memstats_* since before runtime/metrics
// existed. Those names are kept for existing dashboards, but they are
// now read from runtime/metrics rather than runtime.ReadMemStats,
// which stops the world.
type memstatsIndexes struct {
	heapAlloc  int // /memory/classes/heap/objects:bytes
	totalAlloc int // /gc/heap/allocs:bytes
	sys        int // /memory/classes/total:bytes
	mallocs    int // /gc/heap/allocs:objects
	frees      int // /gc/heap/frees:objects
	tinyAllocs int // /gc/heap/tiny/allocs:objects
	numGC      int // /gc/cycles/total:gc-cycles
	gcCPU      int // /cpu/classes/gc/total:cpu-seconds
	gcIdleCPU  int // /cpu/classes/gc/mark/idle:cpu-seconds
	totalCPU   int // /cpu/classes/total:cpu-seconds
}

// runtimeMetrics is the process-wide exporter used by [Handler].
var runtimeMetrics = new(runtimeMetricsExporter)

// runtimeMetricsBufPool holds *[]byte output buffers so that a scrape
// can be formatted under the exporter's lock and written to the
// (possibly slow) client after releasing it.
var runtimeMetricsBufPool = sync.Pool{New: func() any { return new([]byte) }}

// init reads every metric in [runtimeMetricSpecs] once, drops the ones
// this toolchain does not know, and precomputes the per-metric output
// prefixes and histogram layouts.
//
// e.mu must be held.
func (e *runtimeMetricsExporter) init() {
	e.inited = true

	samples := make([]metrics.Sample, len(runtimeMetricSpecs))
	for i, spec := range runtimeMetricSpecs {
		samples[i].Name = spec.name
	}
	metrics.Read(samples)

	byName := map[string]int{}
	for i, spec := range runtimeMetricSpecs {
		s := samples[i]
		var ok bool
		switch s.Value.Kind() {
		case metrics.KindUint64, metrics.KindFloat64:
			ok = spec.typ != "histogram"
		case metrics.KindFloat64Histogram:
			ok = spec.typ == "histogram"
		}
		if !ok {
			// Unknown to this toolchain, or its kind changed
			// out from under our table.
			continue
		}
		st := &runtimeMetricState{spec: spec}
		if !spec.hidden {
			name := runtimeMetricPromName(spec.name, spec.typ)
			st.typeLine = []byte("# TYPE " + name + " " + spec.typ + "\n")
			if spec.typ == "histogram" {
				st.hist = newRuntimeHistLayout(name, s.Value.Float64Histogram().Buckets, spec.buckets)
				st.countPrefix = []byte(name + "_count ")
			} else {
				st.valuePrefix = []byte(name + " ")
			}
		}
		byName[spec.name] = len(e.samples)
		e.samples = append(e.samples, s)
		e.states = append(e.states, st)
	}

	idx := func(name string) int {
		if i, ok := byName[name]; ok {
			return i
		}
		return -1
	}
	e.memstatsIdx = memstatsIndexes{
		heapAlloc:  idx("/memory/classes/heap/objects:bytes"),
		totalAlloc: idx("/gc/heap/allocs:bytes"),
		sys:        idx("/memory/classes/total:bytes"),
		mallocs:    idx("/gc/heap/allocs:objects"),
		frees:      idx("/gc/heap/frees:objects"),
		tinyAllocs: idx("/gc/heap/tiny/allocs:objects"),
		numGC:      idx("/gc/cycles/total:gc-cycles"),
		gcCPU:      idx("/cpu/classes/gc/total:cpu-seconds"),
		gcIdleCPU:  idx("/cpu/classes/gc/mark/idle:cpu-seconds"),
		totalCPU:   idx("/cpu/classes/total:cpu-seconds"),
	}
}

// writeTo reads the current values of the exported metrics and writes
// them to w in Prometheus text format, preceded by the legacy
// memstats_* metrics.
func (e *runtimeMetricsExporter) writeTo(w io.Writer) error {
	bp := runtimeMetricsBufPool.Get().(*[]byte)
	defer runtimeMetricsBufPool.Put(bp)

	e.mu.Lock()
	if !e.inited {
		e.init()
	} else {
		metrics.Read(e.samples)
	}
	*bp = e.appendMemstats((*bp)[:0])
	for i, st := range e.states {
		if !st.spec.hidden {
			*bp = st.appendTo(*bp, &e.samples[i].Value)
		}
	}
	e.mu.Unlock()

	_, err := w.Write(*bp)
	return err
}

// appendTo appends the Prometheus lines for st with value v to b.
func (st *runtimeMetricState) appendTo(b []byte, v *metrics.Value) []byte {
	b = append(b, st.typeLine...)
	switch v.Kind() {
	case metrics.KindUint64:
		b = append(b, st.valuePrefix...)
		b = strconv.AppendUint(b, v.Uint64(), 10)
		b = append(b, '\n')
	case metrics.KindFloat64:
		b = append(b, st.valuePrefix...)
		b = strconv.AppendFloat(b, v.Float64(), 'g', -1, 64)
		b = append(b, '\n')
	case metrics.KindFloat64Histogram:
		counts := v.Float64Histogram().Counts
		var sum uint64
		var next int
		for i, end := range st.hist.ends {
			for ; next < end && next < len(counts); next++ {
				sum += counts[next]
			}
			b = append(b, st.hist.lines[i]...)
			b = strconv.AppendUint(b, sum, 10)
			b = append(b, '\n')
		}
		b = append(b, st.countPrefix...)
		b = strconv.AppendUint(b, sum, 10)
		b = append(b, '\n')
	}
	return b
}

// appendMemstats appends the legacy memstats_* metrics to b, sourced
// from the runtime/metrics samples named by e.memstatsIdx.
//
// e.mu must be held and e.samples must have been read.
func (e *runtimeMetricsExporter) appendMemstats(b []byte) []byte {
	idx := &e.memstatsIdx
	u := func(i int) (uint64, bool) {
		if i < 0 {
			return 0, false
		}
		v := &e.samples[i].Value
		if v.Kind() != metrics.KindUint64 {
			return 0, false
		}
		return v.Uint64(), true
	}
	f := func(i int) (float64, bool) {
		if i < 0 {
			return 0, false
		}
		v := &e.samples[i].Value
		if v.Kind() != metrics.KindFloat64 {
			return 0, false
		}
		return v.Float64(), true
	}
	appendUint := func(typ, name string, v uint64, ok bool, help string) {
		if ok {
			b = appendMemstat(b, typ, name, help)
			b = strconv.AppendUint(b, v, 10)
			b = append(b, '\n')
		}
	}
	appendIdx := func(typ, name string, i int, help string) {
		v, ok := u(i)
		appendUint(typ, name, v, ok, help)
	}
	appendIdx("gauge", "heap_alloc", idx.heapAlloc, "current bytes of allocated heap objects (up/down smoothly)")
	appendIdx("counter", "total_alloc", idx.totalAlloc, "cumulative bytes allocated for heap objects")
	appendIdx("gauge", "sys", idx.sys, "total bytes of memory obtained from the OS")

	// runtime.ReadMemStats counts tiny allocations in both Mallocs
	// and Frees, but /gc/heap/allocs:objects and /gc/heap/frees:objects
	// exclude them, so add them back.
	mallocs, ok1 := u(idx.mallocs)
	frees, ok2 := u(idx.frees)
	tiny, ok3 := u(idx.tinyAllocs)
	appendUint("counter", "mallocs", mallocs+tiny, ok1 && ok3, "cumulative count of heap objects allocated")
	appendUint("counter", "frees", frees+tiny, ok2 && ok3, "cumulative count of heap objects freed")

	appendIdx("counter", "num_gc", idx.numGC, "number of completed GC cycles")
	gc, ok1 := f(idx.gcCPU)
	idle, ok2 := f(idx.gcIdleCPU)
	total, ok3 := f(idx.totalCPU)
	if ok1 && ok2 && ok3 {
		// This is how the runtime computes MemStats.GCCPUFraction:
		// GC time less idle-priority marking, which is "free", over
		// total time. The runtime updates its CPU class stats at
		// the end of each GC cycle, so total is 0 until the first
		// one, as GCCPUFraction was too.
		var frac float64
		if total > 0 {
			frac = (gc - idle) / total
		}
		b = appendMemstat(b, "gauge", "gc_cpu_fraction", "fraction of CPU time used by GC")
		b = strconv.AppendFloat(b, frac, 'f', -1, 64)
		b = append(b, '\n')
	}
	return b
}

// appendMemstat appends the HELP and TYPE lines for the memstats_*
// metric name to b, followed by the metric name and a space, leaving
// the caller to append the value and newline.
func appendMemstat(b []byte, typ, name, help string) []byte {
	b = append(b, "# HELP memstats_"...)
	b = append(b, name...)
	b = append(b, ' ')
	b = append(b, help...)
	b = append(b, "\n# TYPE memstats_"...)
	b = append(b, name...)
	b = append(b, ' ')
	b = append(b, typ...)
	b = append(b, "\nmemstats_"...)
	b = append(b, name...)
	b = append(b, ' ')
	return b
}

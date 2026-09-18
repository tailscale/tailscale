// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package varz

import (
	"bytes"
	"expvar"
	"io"
	"math"
	"net/http/httptest"
	"runtime"
	"runtime/metrics"
	"slices"
	"strconv"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"tailscale.com/util/racebuild"
	"tailscale.com/version"
)

// runtimeMetricDescs returns the runtime's metric descriptions by name.
func runtimeMetricDescs() map[string]metrics.Description {
	m := map[string]metrics.Description{}
	for _, d := range metrics.All() {
		m[d.Name] = d
	}
	return m
}

// TestRuntimeMetricSpecs checks runtimeMetricSpecs against the
// runtime's own metric descriptions: every spec names a real metric
// (or a Tailscale fork metric when not built with the fork), its
// declared Prometheus type matches the metric's kind and
// cumulativeness, and, when built with the fork, every /tailscale/
// metric the fork defines is exported.
func TestRuntimeMetricSpecs(t *testing.T) {
	descs := runtimeMetricDescs()
	seen := map[string]bool{}
	for _, spec := range runtimeMetricSpecs {
		if seen[spec.name] {
			t.Errorf("duplicate spec for %q", spec.name)
		}
		seen[spec.name] = true

		d, ok := descs[spec.name]
		if !ok {
			if strings.HasPrefix(spec.name, "/tailscale/") && !version.IsTailscaleGo() {
				continue
			}
			t.Errorf("spec %q is not a metric in this toolchain", spec.name)
			continue
		}
		var wantTyp string
		switch {
		case d.Kind == metrics.KindFloat64Histogram:
			wantTyp = "histogram"
		case d.Cumulative:
			wantTyp = "counter"
		default:
			wantTyp = "gauge"
		}
		if spec.typ != wantTyp {
			t.Errorf("spec %q has type %q; runtime description implies %q", spec.name, spec.typ, wantTyp)
		}
		if (spec.buckets != 0) != (d.Kind == metrics.KindFloat64Histogram) {
			t.Errorf("spec %q: buckets=%d but kind=%v; histograms and only histograms need a bucket layout", spec.name, spec.buckets, d.Kind)
		}
	}

	if version.IsTailscaleGo() {
		for name := range descs {
			if strings.HasPrefix(name, "/tailscale/") && !seen[name] {
				t.Errorf("Tailscale Go fork metric %q is not in runtimeMetricSpecs", name)
			}
		}
	}
}

func TestRuntimeMetricPromName(t *testing.T) {
	tests := []struct {
		name, typ string
		want      string
	}{
		{"/gc/heap/allocs:bytes", "counter", "go_runtime_gc_heap_allocs_bytes_total"},
		{"/gc/heap/live:bytes", "gauge", "go_runtime_gc_heap_live_bytes"},
		{"/cpu/classes/gc/total:cpu-seconds", "counter", "go_runtime_cpu_classes_gc_total_cpu_seconds_total"},
		{"/sched/goroutines-created:goroutines", "counter", "go_runtime_sched_goroutines_created_goroutines_total"},
		{"/sched/latencies:seconds", "histogram", "go_runtime_sched_latencies_seconds"},
		{"/tailscale/sched/goroutines-by-stack-size:bytes", "histogram", "go_runtime_tailscale_sched_goroutines_by_stack_size_bytes"},
		{"/tailscale/sched/timers/zombies/func:timers", "gauge", "go_runtime_tailscale_sched_timers_zombies_func_timers"},
		{"/gc/heap/allocs:bytes/second", "gauge", "go_runtime_gc_heap_allocs_bytes_per_second"},
	}
	for _, tt := range tests {
		if got := runtimeMetricPromName(tt.name, tt.typ); got != tt.want {
			t.Errorf("runtimeMetricPromName(%q, %q) = %q; want %q", tt.name, tt.typ, got, tt.want)
		}
	}
}

// histLayoutLabels returns the le labels of lay, in order.
func histLayoutLabels(lay *runtimeHistLayout) []string {
	var out []string
	for _, line := range lay.lines {
		s := string(line)
		_, rest, _ := strings.Cut(s, `{le="`)
		le, _, _ := strings.Cut(rest, `"`)
		out = append(out, le)
	}
	return out
}

func TestRuntimeHistLayout(t *testing.T) {
	t.Run("time", func(t *testing.T) {
		// Use the runtime's real time histogram buckets, so this
		// test also notices if the runtime changes its layout.
		s := []metrics.Sample{{Name: "/sched/latencies:seconds"}}
		metrics.Read(s)
		if s[0].Value.Kind() != metrics.KindFloat64Histogram {
			t.Fatalf("unexpected kind %v", s[0].Value.Kind())
		}
		buckets := s[0].Value.Float64Histogram().Buckets
		t.Logf("runtime has %d time histogram buckets", len(buckets)-1)

		lay := newRuntimeHistLayout("m", buckets, histTime)
		want := []string{
			"2.56e-07", "1.024e-06", "4.096e-06", "1.6384e-05", "6.5536e-05",
			"0.000262144", "0.001048576", "0.004194304", "0.016777216",
			"0.067108864", "0.268435456", "1.073741824", "+Inf",
		}
		if got := histLayoutLabels(lay); !slices.Equal(got, want) {
			t.Errorf("labels = %q; want %q", got, want)
		}
		if got, want := lay.ends[len(lay.ends)-1], len(buckets)-1; got != want {
			t.Errorf("+Inf bucket covers %d runtime buckets; want all %d", got, want)
		}
		if !slices.IsSorted(lay.ends) {
			t.Errorf("ends not sorted: %v", lay.ends)
		}
		// Each merged boundary must be an actual runtime boundary,
		// so no runtime bucket is split.
		for i, end := range lay.ends[:len(lay.ends)-1] {
			le := want[i]
			if got := formatLE(buckets[end]); got != le {
				t.Errorf("output bucket %d ends at runtime boundary %v; label says %v", i, got, le)
			}
		}
	})

	t.Run("ints", func(t *testing.T) {
		// The fork's func zombie lifetime histogram: 0, 1, then
		// powers of two, then +Inf, counting whole GC cycles.
		buckets := []float64{0, 1, 2, 4, 8, math.Inf(1)}
		lay := newRuntimeHistLayout("m", buckets, histInts)
		want := []string{"0", "1", "3", "7", "+Inf"}
		if got := histLayoutLabels(lay); !slices.Equal(got, want) {
			t.Errorf("labels = %q; want %q", got, want)
		}
		if want := []int{1, 2, 3, 4, 5}; !slices.Equal(lay.ends, want) {
			t.Errorf("ends = %v; want %v", lay.ends, want)
		}

		st := &runtimeMetricState{hist: lay, countPrefix: []byte("m_count ")}
		var v metrics.Value
		setHistValue(t, &v, buckets, []uint64{10, 3, 2, 1, 4})
		got := string(st.appendTo(nil, &v))
		const wantOut = "m_bucket{le=\"0\"} 10\n" +
			"m_bucket{le=\"1\"} 13\n" +
			"m_bucket{le=\"3\"} 15\n" +
			"m_bucket{le=\"7\"} 16\n" +
			"m_bucket{le=\"+Inf\"} 20\n" +
			"m_count 20\n"
		if got != wantOut {
			t.Errorf("got:\n%s\nwant:\n%s", got, wantOut)
		}
	})

	t.Run("powers_of_two", func(t *testing.T) {
		buckets := []float64{2048, 4096, 8192, 16384, math.Inf(1)}
		lay := newRuntimeHistLayout("m", buckets, histPowersOfTwo)
		want := []string{"2048", "4096", "8192", "+Inf"}
		if got := histLayoutLabels(lay); !slices.Equal(got, want) {
			t.Errorf("labels = %q; want %q", got, want)
		}
		if want := []int{1, 2, 3, 4}; !slices.Equal(lay.ends, want) {
			t.Errorf("ends = %v; want %v", lay.ends, want)
		}

		// A value exactly at a lower bound lands in the bucket
		// labeled with that value.
		st := &runtimeMetricState{hist: lay, countPrefix: []byte("m_count ")}
		var v metrics.Value
		setHistValue(t, &v, buckets, []uint64{5, 0, 2, 1})
		got := string(st.appendTo(nil, &v))
		const wantOut = "m_bucket{le=\"2048\"} 5\n" +
			"m_bucket{le=\"4096\"} 5\n" +
			"m_bucket{le=\"8192\"} 7\n" +
			"m_bucket{le=\"+Inf\"} 8\n" +
			"m_count 8\n"
		if got != wantOut {
			t.Errorf("got:\n%s\nwant:\n%s", got, wantOut)
		}
	})
}

// formatLE formats f the way runtime histogram le labels are formatted.
func formatLE(f float64) string {
	if math.IsInf(f, 1) {
		return "+Inf"
	}
	return string(strconv.AppendFloat(nil, f, 'g', -1, 64))
}

// setHistValue makes v a histogram value with the given buckets and
// counts, by reading a real histogram metric and overwriting its
// storage, since runtime/metrics offers no constructor.
func setHistValue(t *testing.T, v *metrics.Value, buckets []float64, counts []uint64) {
	t.Helper()
	s := []metrics.Sample{{Name: "/sched/latencies:seconds"}}
	metrics.Read(s)
	h := s[0].Value.Float64Histogram()
	if h == nil {
		t.Fatal("no histogram")
	}
	h.Buckets = buckets
	h.Counts = counts
	*v = s[0].Value
}

// parseProm parses Prometheus text format, failing the test on error.
func parseProm(t *testing.T, b []byte) map[string]*dto.MetricFamily {
	t.Helper()
	p := expfmt.NewTextParser(model.LegacyValidation)
	fams, err := p.TextToMetricFamilies(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("parsing Prometheus output: %v\n%s", err, b)
	}
	return fams
}

func TestRuntimeMetricsExporter(t *testing.T) {
	var buf bytes.Buffer
	if err := runtimeMetrics.writeTo(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	t.Logf("output:\n%s", out)
	fams := parseProm(t, out)

	// Every spec that this toolchain supports must appear with the
	// right type.
	descs := runtimeMetricDescs()
	for _, spec := range runtimeMetricSpecs {
		if _, ok := descs[spec.name]; !ok {
			continue
		}
		if spec.hidden {
			if _, ok := fams[runtimeMetricPromName(spec.name, spec.typ)]; ok {
				t.Errorf("hidden spec %q was exported", spec.name)
			}
			continue
		}
		name := runtimeMetricPromName(spec.name, spec.typ)
		fam, ok := fams[name]
		if !ok {
			t.Errorf("no output for %q (%s)", spec.name, name)
			continue
		}
		var wantTyp dto.MetricType
		switch spec.typ {
		case "counter":
			wantTyp = dto.MetricType_COUNTER
		case "gauge":
			wantTyp = dto.MetricType_GAUGE
		case "histogram":
			wantTyp = dto.MetricType_HISTOGRAM
		}
		if fam.GetType() != wantTyp {
			t.Errorf("%s: type %v; want %v", name, fam.GetType(), wantTyp)
		}
		if spec.typ == "histogram" {
			h := fam.GetMetric()[0].GetHistogram()
			if len(h.GetBucket()) == 0 {
				t.Errorf("%s: no buckets", name)
			}
			var prev uint64
			for _, b := range h.GetBucket() {
				if b.GetCumulativeCount() < prev {
					t.Errorf("%s: bucket counts not cumulative", name)
				}
				prev = b.GetCumulativeCount()
			}
			if h.GetSampleCount() != prev {
				t.Errorf("%s: count %d != last bucket %d", name, h.GetSampleCount(), prev)
			}
		}
	}

	// The legacy memstats_* names must still be exported with their
	// old types and plausible values.
	memstats := []struct {
		name string
		typ  dto.MetricType
	}{
		{"memstats_heap_alloc", dto.MetricType_GAUGE},
		{"memstats_total_alloc", dto.MetricType_COUNTER},
		{"memstats_sys", dto.MetricType_GAUGE},
		{"memstats_mallocs", dto.MetricType_COUNTER},
		{"memstats_frees", dto.MetricType_COUNTER},
		{"memstats_num_gc", dto.MetricType_COUNTER},
		{"memstats_gc_cpu_fraction", dto.MetricType_GAUGE},
	}
	for _, ms := range memstats {
		fam, ok := fams[ms.name]
		if !ok {
			t.Errorf("missing %s", ms.name)
			continue
		}
		if fam.GetType() != ms.typ {
			t.Errorf("%s: type %v; want %v", ms.name, fam.GetType(), ms.typ)
		}
		if fam.GetHelp() == "" {
			t.Errorf("%s: no HELP", ms.name)
		}
	}
	if v := fams["memstats_sys"].GetMetric()[0].GetGauge().GetValue(); v <= 0 {
		t.Errorf("memstats_sys = %v; want > 0", v)
	}
	if v := fams["memstats_gc_cpu_fraction"].GetMetric()[0].GetGauge().GetValue(); v < 0 || v > 1 {
		t.Errorf("memstats_gc_cpu_fraction = %v; want in [0, 1]", v)
	}

	if version.IsTailscaleGo() {
		fam, ok := fams["go_runtime_tailscale_sched_goroutines_by_stack_size_bytes"]
		if !ok {
			t.Fatal("missing stack size histogram under tailscale_go")
		}
		h := fam.GetMetric()[0].GetHistogram()
		if h.GetSampleCount() == 0 {
			t.Error("stack size histogram counts no goroutines")
		}
		// The first bucket is the minimum stack size, 2 KiB on most
		// platforms but larger on some, and always a power of two.
		if got := h.GetBucket()[0].GetUpperBound(); got < 2048 || math.Log2(got) != math.Trunc(math.Log2(got)) {
			t.Errorf("first stack size bucket is %v; want a power of two >= 2048", got)
		}
	} else {
		for name := range fams {
			if strings.Contains(name, "tailscale") {
				t.Errorf("unexpected fork metric %q without tailscale_go", name)
			}
		}
	}
}

// TestVarzHandlerRuntimeMetrics checks that Handler includes the
// runtime metrics and skips the expvar package's stop-the-world
// memstats var, and that the whole output parses.
func TestVarzHandlerRuntimeMetrics(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler(rec, httptest.NewRequest("GET", "/", nil))
	out := rec.Body.Bytes()
	fams := parseProm(t, out)
	for _, name := range []string{
		"go_runtime_gc_heap_live_bytes",
		"go_runtime_cpu_classes_gc_total_cpu_seconds_total",
		"go_runtime_sched_latencies_seconds",
		"memstats_heap_alloc",
	} {
		if _, ok := fams[name]; !ok {
			t.Errorf("missing %s", name)
		}
	}
	if n := bytes.Count(out, []byte("\nmemstats_heap_alloc ")); n != 1 {
		t.Errorf("memstats_heap_alloc appears %d times; want 1", n)
	}
	if bytes.Contains(out, []byte(`skipping expvar "memstats"`)) {
		t.Errorf("output mentions skipping memstats; it should not be reached at all")
	}
}

// TestMemstatsMatchReadMemStats checks that the memstats_* values
// computed from runtime/metrics agree with the runtime.MemStats fields
// they replaced, read back to back in the same process.
func TestMemstatsMatchReadMemStats(t *testing.T) {
	// Make sure at least one GC has happened so the CPU stats and
	// GCCPUFraction are populated, then read both as close together
	// as possible. The exporter's first call allocates, so warm it.
	runtime.GC()
	runtimeMetrics.writeTo(io.Discard)
	var buf bytes.Buffer
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	runtimeMetrics.writeTo(&buf)
	fams := parseProm(t, buf.Bytes())

	get := func(name string) float64 {
		t.Helper()
		fam, ok := fams[name]
		if !ok {
			t.Fatalf("missing %s", name)
		}
		m := fam.GetMetric()[0]
		if fam.GetType() == dto.MetricType_COUNTER {
			return m.GetCounter().GetValue()
		}
		return m.GetGauge().GetValue()
	}
	// Anything allocated between the two reads shows up as a small
	// difference, so allow a little slack on the heap numbers. The GC
	// cycle count and the GC CPU fraction only change at GC, which
	// runtime.GC just did, so they should match closely.
	check := func(name string, want, relTol, absTol float64) {
		t.Helper()
		got := get(name)
		diff := math.Abs(got - want)
		if diff > absTol && diff > relTol*math.Abs(want) {
			t.Errorf("%s = %v; runtime.MemStats says %v", name, got, want)
		}
	}
	check("memstats_heap_alloc", float64(ms.HeapAlloc), 0, 64<<10)
	check("memstats_total_alloc", float64(ms.TotalAlloc), 0, 64<<10)
	check("memstats_sys", float64(ms.Sys), 0.01, 0)
	check("memstats_mallocs", float64(ms.Mallocs), 0, 50)
	check("memstats_frees", float64(ms.Frees), 0, 50)
	check("memstats_num_gc", float64(ms.NumGC), 0, 1)
	check("memstats_gc_cpu_fraction", ms.GCCPUFraction, 0, 1e-6)
	t.Logf("gc_cpu_fraction: runtime/metrics=%v MemStats=%v", get("memstats_gc_cpu_fraction"), ms.GCCPUFraction)
}

// TestWritePrometheusExpvarSkipsMemstats checks that callers walking
// expvar.Do themselves (as some corp code does) also never trigger the
// stop-the-world memstats func.
func TestWritePrometheusExpvarSkipsMemstats(t *testing.T) {
	v := expvar.Get("memstats")
	if v == nil {
		t.Fatal("expvar package did not publish memstats")
	}
	var buf bytes.Buffer
	WritePrometheusExpvar(&buf, expvar.KeyValue{Key: "memstats", Value: v})
	if buf.Len() != 0 {
		t.Errorf("got output for memstats expvar; want none:\n%s", buf.String())
	}
}

func TestRuntimeMetricsExporterAllocs(t *testing.T) {
	if racebuild.On {
		t.Skip("allocation counts differ under the race detector")
	}
	e := new(runtimeMetricsExporter)
	e.writeTo(io.Discard) // init
	e.writeTo(io.Discard) // grow the pooled buffer
	if allocs := testing.AllocsPerRun(100, func() {
		e.writeTo(io.Discard)
	}); allocs != 0 {
		t.Errorf("allocs per scrape = %v; want 0", allocs)
	}
}

func BenchmarkRuntimeMetricsExporter(b *testing.B) {
	e := new(runtimeMetricsExporter)
	e.writeTo(io.Discard)
	b.ReportAllocs()
	for b.Loop() {
		e.writeTo(io.Discard)
	}
}

func BenchmarkVarzHandler(b *testing.B) {
	req := httptest.NewRequest("GET", "/", nil)
	rec := new(httptest.ResponseRecorder) // no body, so writes are discarded
	b.ReportAllocs()
	for b.Loop() {
		Handler(rec, req)
	}
}

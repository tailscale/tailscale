// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package metrics

import (
	"io"
	"math"
	"os"
	"runtime"
	"strings"
	"testing"

	"tailscale.com/tstest"
)

func TestLabelMap(t *testing.T) {
	var m LabelMap
	m.GetIncrFunc("foo")(1)
	m.GetIncrFunc("bar")(2)
	if g, w := m.Get("foo").Value(), int64(1); g != w {
		t.Errorf("foo = %v; want %v", g, w)
	}
	if g, w := m.Get("bar").Value(), int64(2); g != w {
		t.Errorf("bar = %v; want %v", g, w)
	}
	m.GetShardedInt("sharded").Add(5)
	if g, w := m.GetShardedInt("sharded").Value(), int64(5); g != w {
		t.Errorf("sharded = %v; want %v", g, w)
	}
	m.Add("sharded", 1)
	if g, w := m.GetShardedInt("sharded").Value(), int64(6); g != w {
		t.Errorf("sharded = %v; want %v", g, w)
	}
	m.Add("neverbefore", 1)
}

func TestCurrentFileDescriptors(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("skipping on %v", runtime.GOOS)
	}
	n := CurrentFDs()
	if n < 3 {
		t.Fatalf("got %v; want >= 3", n)
	}

	err := tstest.MinAllocsPerRun(t, 0, func() {
		n = CurrentFDs()
	})
	if err != nil {
		t.Fatal(err)
	}

	// Open some FDs.
	const extra = 10
	for i := range extra {
		f, err := os.Open("/proc/self/stat")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		t.Logf("fds for #%v = %v", i, CurrentFDs())
	}

	n2 := CurrentFDs()
	if n2 < n+extra {
		t.Errorf("fds changed from %v => %v, want to %v", n, n2, n+extra)
	}
}

func promString(h *Histogram, name string) string {
	var sb strings.Builder
	h.PromExport(&sb, name)
	return sb.String()
}

func TestHistogram(t *testing.T) {
	tests := []struct {
		name     string
		buckets  []float64
		obs      []float64
		want     string
		wantProm string
	}{
		{
			name:    "empty",
			buckets: []float64{1, 2, 5},
			want:    `{"1": 0,"2": 0,"5": 0,"+Inf": 0,"sum": 0,"count": 0}`,
			wantProm: "# TYPE test_hist histogram\n" +
				"test_hist_bucket{le=\"1\"} 0\n" +
				"test_hist_bucket{le=\"2\"} 0\n" +
				"test_hist_bucket{le=\"5\"} 0\n" +
				"test_hist_bucket{le=\"+Inf\"} 0\n" +
				"test_hist_sum 0\n" +
				"test_hist_count 0\n",
		},
		{
			// Boundary values count in their own bucket; 7 is
			// above the largest bucket and only moves +Inf,
			// sum, and count.
			name:    "filled",
			buckets: []float64{1, 2, 5},
			obs:     []float64{0.5, 1, 1.5, 5, 7, -3},
			want:    `{"1": 3,"2": 4,"5": 5,"+Inf": 6,"sum": 12,"count": 6}`,
			wantProm: "# TYPE test_hist histogram\n" +
				"test_hist_bucket{le=\"1\"} 3\n" +
				"test_hist_bucket{le=\"2\"} 4\n" +
				"test_hist_bucket{le=\"5\"} 5\n" +
				"test_hist_bucket{le=\"+Inf\"} 6\n" +
				"test_hist_sum 12\n" +
				"test_hist_count 6\n",
		},
		{
			name:    "derp-like",
			buckets: []float64{536, 1400, 1460},
			obs:     []float64{1400, 1460},
			want:    `{"536": 0,"1400": 1,"1460": 2,"+Inf": 2,"sum": 2860,"count": 2}`,
			wantProm: "# TYPE test_hist histogram\n" +
				"test_hist_bucket{le=\"536\"} 0\n" +
				"test_hist_bucket{le=\"1400\"} 1\n" +
				"test_hist_bucket{le=\"1460\"} 2\n" +
				"test_hist_bucket{le=\"+Inf\"} 2\n" +
				"test_hist_sum 2860\n" +
				"test_hist_count 2\n",
		},
		{
			name:    "no buckets",
			buckets: nil,
			obs:     []float64{42},
			want:    `{"+Inf": 1,"sum": 42,"count": 1}`,
			wantProm: "# TYPE test_hist histogram\n" +
				"test_hist_bucket{le=\"+Inf\"} 1\n" +
				"test_hist_sum 42\n" +
				"test_hist_count 1\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHistogram(tt.buckets)
			for _, v := range tt.obs {
				h.Observe(v)
			}
			if got := h.String(); got != tt.want {
				t.Errorf("String() = %s; want %s", got, tt.want)
			}
			if got := promString(h, "test_hist"); got != tt.wantProm {
				t.Errorf("PromExport = %q; want %q", got, tt.wantProm)
			}
		})
	}
}

func TestHistogramPerBucketCounts(t *testing.T) {
	// Observe must store non-cumulative per-bucket counts;
	// cumulative counts are computed at read time.
	h := NewHistogram([]float64{1, 2, 5})
	for _, v := range []float64{0.5, 1, 1.5, 5, 7, -3} {
		h.Observe(v)
	}
	want := []int64{3, 1, 1}
	for i, w := range want {
		if got := h.bucketVars[i].Value(); got != w {
			t.Errorf("bucketVars[%d] = %d; want %d", i, got, w)
		}
	}
}

func TestHistogramNaNAndInf(t *testing.T) {
	// A NaN observation increments no finite bucket (every
	// >= comparison against NaN is false); only sum and count
	// move. The resulting "sum": NaN is pre-existing output,
	// locked here byte-for-byte.
	h := NewHistogram([]float64{1, 2})
	h.Observe(math.NaN())
	if got, want := h.String(), `{"1": 0,"2": 0,"+Inf": 1,"sum": NaN,"count": 1}`; got != want {
		t.Errorf("NaN String() = %s; want %s", got, want)
	}

	h = NewHistogram([]float64{1, 2})
	h.Observe(math.Inf(1))
	if got, want := h.String(), `{"1": 0,"2": 0,"+Inf": 1,"sum": +Inf,"count": 1}`; got != want {
		t.Errorf("+Inf String() = %s; want %s", got, want)
	}

	h = NewHistogram([]float64{1, 2})
	h.Observe(math.Inf(-1))
	if got, want := h.String(), `{"1": 1,"2": 1,"+Inf": 1,"sum": -Inf,"count": 1}`; got != want {
		t.Errorf("-Inf String() = %s; want %s", got, want)
	}
}

func TestNewHistogramPanicsUnsorted(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewHistogram with unsorted buckets did not panic")
		}
	}()
	NewHistogram([]float64{5, 1})
}

func BenchmarkHistogramObserve(b *testing.B) {
	buckets := []float64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 25, 50, 100}
	for _, tc := range []struct {
		name string
		v    float64
	}{
		{"FirstBucket", 0},
		{"MiddleBucket", 9},
		{"AboveMax", 1000},
	} {
		b.Run(tc.name, func(b *testing.B) {
			h := NewHistogram(buckets)
			b.ReportAllocs()
			for range b.N {
				h.Observe(tc.v)
			}
		})
	}
}

func BenchmarkHistogramString(b *testing.B) {
	h := NewHistogram([]float64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 25, 50, 100})
	h.Observe(9)
	b.ReportAllocs()
	for range b.N {
		_ = h.String()
	}
}

func BenchmarkHistogramPromExport(b *testing.B) {
	h := NewHistogram([]float64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 25, 50, 100})
	h.Observe(9)
	b.ReportAllocs()
	for range b.N {
		h.PromExport(io.Discard, "bench_hist")
	}
}

func BenchmarkCurrentFileDescriptors(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		_ = CurrentFDs()
	}
}

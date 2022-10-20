// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
	"expvar"
	"os"
	"runtime"
	"testing"

	"tailscale.com/tstest"
)

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
	for i := 0; i < extra; i++ {
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

func BenchmarkCurrentFileDescriptors(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = CurrentFDs()
	}
}

func TestDistribution(t *testing.T) {
	d := &Distribution{
		Map: expvar.Map{},
		Bins: []float64{
			2, 3, 5, 8, 13,
		},
	}

	t.Run("Single", func(t *testing.T) {
		d.AddFloat(1.0)
		const expected = `{"2": 1, "count": 1, "max": 1, "min": 1}`
		if ss := d.String(); ss != expected {
			t.Errorf("got %q; want %q", ss, expected)
		}
	})

	t.Run("Additional", func(t *testing.T) {
		d.AddFloat(1.5)
		d.AddFloat(2.5)
		d.AddFloat(7)
		d.AddFloat(15)
		const expected = `{"2": 2, "3": 1, "8": 1, "count": 5, "inf": 1, "max": 15, "min": 1}`
		if ss := d.String(); ss != expected {
			t.Errorf("got %q; want %q", ss, expected)
		}
	})
}

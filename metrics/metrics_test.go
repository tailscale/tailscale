// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package metrics

import (
	"os"
	"runtime"
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

func BenchmarkCurrentFileDescriptors(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		_ = CurrentFDs()
	}
}

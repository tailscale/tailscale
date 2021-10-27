// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
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

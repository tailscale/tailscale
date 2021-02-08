// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstest

import (
	"bytes"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func ResourceCheck(tb testing.TB) {
	startN, startStacks := goroutines()
	tb.Cleanup(func() {
		if tb.Failed() {
			// Something else went wrong.
			return
		}
		tb.Helper()
		// Goroutines might be still exiting.
		for i := 0; i < 100; i++ {
			if runtime.NumGoroutine() <= startN {
				return
			}
			time.Sleep(1 * time.Millisecond)
		}
		endN, endStacks := goroutines()
		tb.Logf("goroutine diff:\n%v\n", cmp.Diff(startStacks, endStacks))
		tb.Fatalf("goroutine count: expected %d, got %d\n", startN, endN)
	})
}

func goroutines() (int, []byte) {
	p := pprof.Lookup("goroutine")
	b := new(bytes.Buffer)
	p.WriteTo(b, 1)
	return p.Count(), b.Bytes()
}

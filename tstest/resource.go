// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstest

import (
	"bytes"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// ResourceCheck takes a snapshot of the current goroutines and registers a
// cleanup on tb to verify that after the rest, all goroutines created by the
// test go away. (well, at least that the count matches. Maybe in the future it
// can look at specific routines).
//
// It panics if called from a parallel test.
func ResourceCheck(tb testing.TB) {
	tb.Helper()

	// Set an environment variable (anything at all) just for the
	// side effect of tb.Setenv panicking if we're in a parallel test.
	tb.Setenv("TS_CHECKING_RESOURCES", "1")

	startN, startStacks := goroutines()
	tb.Cleanup(func() {
		if tb.Failed() {
			// Something else went wrong.
			return
		}
		// Goroutines might be still exiting.
		for range 300 {
			if runtime.NumGoroutine() <= startN {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		endN, endStacks := goroutines()
		if endN <= startN {
			return
		}
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

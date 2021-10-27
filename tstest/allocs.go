// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstest

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// MinAllocsPerRun asserts that f can run with no more than target allocations.
// It runs f up to 1000 times or 5s, whichever happens first.
// If f has executed more than target allocations on every run, it returns a non-nil error.
//
// MinAllocsPerRun sets GOMAXPROCS to 1 during its measurement and restores
// it before returning.
func MinAllocsPerRun(t *testing.T, target uint64, f func()) error {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))

	var memstats runtime.MemStats
	var min, max, sum uint64
	start := time.Now()
	var iters int
	for {
		runtime.ReadMemStats(&memstats)
		startMallocs := memstats.Mallocs
		f()
		runtime.ReadMemStats(&memstats)
		mallocs := memstats.Mallocs - startMallocs
		// TODO: if mallocs < target, return an error? See discussion in #3204.
		if mallocs <= target {
			return nil
		}
		if min == 0 || mallocs < min {
			min = mallocs
		}
		if mallocs > max {
			max = mallocs
		}
		sum += mallocs
		iters++
		if iters == 1000 || time.Since(start) > 5*time.Second {
			break
		}
	}

	return fmt.Errorf("min allocs = %d, max allocs = %d, avg allocs/run = %f, want run with <= %d allocs", min, max, float64(sum)/float64(iters), target)
}

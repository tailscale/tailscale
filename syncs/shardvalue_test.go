// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syncs

import (
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/cpu"
)

func TestShardValue(t *testing.T) {
	type intVal struct {
		atomic.Int64
		_ cpu.CacheLinePad
	}

	t.Run("One", func(t *testing.T) {
		sv := NewShardValue[intVal]()
		sv.One(func(v *intVal) {
			v.Store(10)
		})

		var v int64
		for i := range sv.shards {
			v += sv.shards[i].Load()
		}
		if v != 10 {
			t.Errorf("got %v, want 10", v)
		}
	})

	t.Run("All", func(t *testing.T) {
		sv := NewShardValue[intVal]()
		for i := range sv.shards {
			sv.shards[i].Store(int64(i))
		}

		var total int64
		sv.All(func(v *intVal) bool {
			total += v.Load()
			return true
		})
		// triangle coefficient lower one order due to 0 index
		want := int64(len(sv.shards) * (len(sv.shards) - 1) / 2)
		if total != want {
			t.Errorf("got %v, want %v", total, want)
		}
	})

	t.Run("Len", func(t *testing.T) {
		sv := NewShardValue[intVal]()
		if got, want := sv.Len(), runtime.NumCPU(); got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("distribution", func(t *testing.T) {
		sv := NewShardValue[intVal]()

		goroutines := 1000
		iterations := 10000
		var wg sync.WaitGroup
		wg.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				for i := 0; i < iterations; i++ {
					sv.One(func(v *intVal) {
						v.Add(1)
					})
				}
			}()
		}
		wg.Wait()

		var (
			total        int64
			distribution []int64
		)
		t.Logf("distribution:")
		sv.All(func(v *intVal) bool {
			total += v.Load()
			distribution = append(distribution, v.Load())
			t.Logf("%d", v.Load())
			return true
		})

		if got, want := total, int64(goroutines*iterations); got != want {
			t.Errorf("got %v, want %v", got, want)
		}
		if got, want := len(distribution), runtime.NumCPU(); got != want {
			t.Errorf("got %v, want %v", got, want)
		}

		mean := total / int64(len(distribution))
		for _, v := range distribution {
			if v < mean/10 || v > mean*10 {
				t.Logf("distribution is very unbalanced: %v", distribution)
			}
		}
		t.Logf("mean:  %d", mean)

		var standardDev int64
		for _, v := range distribution {
			standardDev += ((v - mean) * (v - mean))
		}
		standardDev = int64(math.Sqrt(float64(standardDev / int64(len(distribution)))))
		t.Logf("stdev: %d", standardDev)

		if standardDev > mean/3 {
			t.Logf("standard deviation is too high: %v", standardDev)
		}
	})
}

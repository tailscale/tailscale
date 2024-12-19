// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syncs

import (
	"expvar"
	"sync"
	"testing"
)

func BenchmarkShardedInt(b *testing.B) {
	b.ReportAllocs()

	b.Run("expvar", func(b *testing.B) {
		var m expvar.Int
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				m.Add(1)
			}
		})
	})

	b.Run("sharded int", func(b *testing.B) {
		m := NewShardedInt()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				m.Add(1)
			}
		})
	})
}

func TestShardedInt(t *testing.T) {
	t.Run("basics", func(t *testing.T) {
		m := NewShardedInt()
		if got, want := m.Value(), int64(0); got != want {
			t.Errorf("got %v, want %v", got, want)
		}
		m.Add(1)
		if got, want := m.Value(), int64(1); got != want {
			t.Errorf("got %v, want %v", got, want)
		}
		m.Add(2)
		if got, want := m.Value(), int64(3); got != want {
			t.Errorf("got %v, want %v", got, want)
		}
		m.Add(-1)
		if got, want := m.Value(), int64(2); got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("high concurrency", func(t *testing.T) {
		m := NewShardedInt()
		wg := sync.WaitGroup{}
		numWorkers := 1000
		numIncrements := 1000
		wg.Add(numWorkers)
		for i := 0; i < numWorkers; i++ {
			go func() {
				defer wg.Done()
				for i := 0; i < numIncrements; i++ {
					m.Add(1)
				}
			}()
		}
		wg.Wait()
		if got, want := m.Value(), int64(numWorkers*numIncrements); got != want {
			t.Errorf("got %v, want %v", got, want)
		}
		for i, shard := range m.GetDistribution() {
			t.Logf("shard %d: %d", i, shard)
		}
	})
}

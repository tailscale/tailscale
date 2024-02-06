// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package rands

import (
	"math/rand"
	"sync"
	"testing"

	exprand "golang.org/x/exp/rand"
)

var (
	seed          uint64 = 8729831
	numDraw              = 100
	numGoroutines        = 5000
)

type workerPool struct {
	job chan func()
	res chan struct{}
	wg  sync.WaitGroup
}

func (p *workerPool) Close() {
	close(p.job)
	p.wg.Wait()
}

func newWorkerPool() *workerPool {
	pool := workerPool{
		job: make(chan func(), 2<<20),
		res: make(chan struct{}, 2<<20),
		wg:  sync.WaitGroup{},
	}
	for i := 0; i < numGoroutines; i++ {
		pool.wg.Add(1)
		go func() {
			defer pool.wg.Done()
			for f := range pool.job {
				f()
				pool.res <- struct{}{}
			}
		}()
	}
	return &pool
}

var stdPool = sync.Pool{
	New: func() any {
		return rand.New(rand.NewSource(int64(seed)))
	},
}

var expPool = sync.Pool{
	New: func() any {
		return exprand.New(exprand.NewSource(seed))
	},
}

func BenchmarkStd(b *testing.B) {
	pool := newWorkerPool()
	defer pool.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pool.job <- func() {
			rand.Seed(int64(seed))
			for i := 0; i < numDraw; i++ {
				rand.Intn(100)
			}
		}
	}
	for i := 0; i < b.N; i++ {
		<-pool.res
	}
}

func BenchmarkPCG(b *testing.B) {
	pool := newWorkerPool()
	defer pool.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pool.job <- func() {
			exprand.Seed(seed)
			for i := 0; i < numDraw; i++ {
				exprand.Intn(100)
			}
		}
	}
	for i := 0; i < b.N; i++ {
		<-pool.res
	}
}

func BenchmarkStdPool(b *testing.B) {
	pool := newWorkerPool()
	defer pool.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pool.job <- func() {
			r := stdPool.Get().(*rand.Rand)
			defer stdPool.Put(r)

			r.Seed(int64(seed))
			for i := 0; i < numDraw; i++ {
				r.Intn(100)
			}
		}
	}
	for i := 0; i < b.N; i++ {
		<-pool.res
	}
}

func BenchmarkPCGPool(b *testing.B) {
	pool := newWorkerPool()
	defer pool.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pool.job <- func() {
			r := expPool.Get().(*exprand.Rand)
			defer expPool.Put(r)

			r.Seed(seed)
			for i := 0; i < numDraw; i++ {
				r.Intn(100)
			}
		}
	}
	for i := 0; i < b.N; i++ {
		<-pool.res
	}
}

func BenchmarkLocalStd(b *testing.B) {
	pool := newWorkerPool()
	defer pool.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pool.job <- func() {
			r := rand.New(rand.NewSource(int64(seed)))
			for i := 0; i < numDraw; i++ {
				r.Intn(100)
			}
		}
	}
	for i := 0; i < b.N; i++ {
		<-pool.res
	}
}

func BenchmarkLocalPCG(b *testing.B) {
	pool := newWorkerPool()
	defer pool.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pool.job <- func() {
			r := exprand.New(exprand.NewSource(seed))
			for i := 0; i < numDraw; i++ {
				r.Intn(100)
			}
		}
	}
	for i := 0; i < b.N; i++ {
		<-pool.res
	}
}

func BenchmarkStackRand(b *testing.B) {
	pool := newWorkerPool()
	defer pool.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pool.job <- func() {
			r := NewRand(seed)
			for i := 0; i < numDraw; i++ {
				r.Intn(100)
			}
		}
	}
	for i := 0; i < b.N; i++ {
		<-pool.res
	}
}

func TestStackRandNoAllocs(t *testing.T) {
	seed := rand.Uint64()
	if n := testing.AllocsPerRun(1000, func() {
		r := NewRand(seed)
		_ = r.Intn(100)
	}); n > 0 {
		t.Errorf("Rand got %v allocs per run", n)
	}

}

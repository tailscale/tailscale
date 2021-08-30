// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This is a modified, simplified version of code from golang.org/x/time/rate.

// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.7
// +build go1.7

package rate

import (
	"context"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tstime/mono"
)

func closeEnough(a, b Limit) bool {
	return (math.Abs(float64(a)/float64(b)) - 1.0) < 1e-9
}

func TestEvery(t *testing.T) {
	cases := []struct {
		interval time.Duration
		lim      Limit
	}{
		{1 * time.Nanosecond, Limit(1e9)},
		{1 * time.Microsecond, Limit(1e6)},
		{1 * time.Millisecond, Limit(1e3)},
		{10 * time.Millisecond, Limit(100)},
		{100 * time.Millisecond, Limit(10)},
		{1 * time.Second, Limit(1)},
		{2 * time.Second, Limit(0.5)},
		{time.Duration(2.5 * float64(time.Second)), Limit(0.4)},
		{4 * time.Second, Limit(0.25)},
		{10 * time.Second, Limit(0.1)},
		{time.Duration(math.MaxInt64), Limit(1e9 / float64(math.MaxInt64))},
	}
	for _, tc := range cases {
		lim := Every(tc.interval)
		if !closeEnough(lim, tc.lim) {
			t.Errorf("Every(%v) = %v want %v", tc.interval, lim, tc.lim)
		}
	}
}

const (
	d = 100 * time.Millisecond
)

var (
	t0 = mono.Now()
	t1 = t0.Add(time.Duration(1) * d)
	t2 = t0.Add(time.Duration(2) * d)
	t3 = t0.Add(time.Duration(3) * d)
	t4 = t0.Add(time.Duration(4) * d)
	t5 = t0.Add(time.Duration(5) * d)
	t9 = t0.Add(time.Duration(9) * d)
)

type allow struct {
	t  mono.Time
	ok bool
}

func run(t *testing.T, lim *Limiter, allows []allow) {
	t.Helper()
	for i, allow := range allows {
		ok := lim.allow(allow.t)
		if ok != allow.ok {
			t.Errorf("step %d: lim.AllowN(%v) = %v want %v",
				i, allow.t, ok, allow.ok)
		}
	}
}

func TestLimiterBurst1(t *testing.T) {
	run(t, NewLimiter(10, 1), []allow{
		{t0, true},
		{t0, false},
		{t0, false},
		{t1, true},
		{t1, false},
		{t1, false},
		{t2, true},
		{t2, false},
	})
}

func TestLimiterJumpBackwards(t *testing.T) {
	run(t, NewLimiter(10, 3), []allow{
		{t1, true}, // start at t1
		{t0, true}, // jump back to t0, two tokens remain
		{t0, true},
		{t0, false},
		{t0, false},
		{t1, true}, // got a token
		{t1, false},
		{t1, false},
		{t2, true}, // got another token
		{t2, false},
		{t2, false},
	})
}

// Ensure that tokensFromDuration doesn't produce
// rounding errors by truncating nanoseconds.
// See golang.org/issues/34861.
func TestLimiter_noTruncationErrors(t *testing.T) {
	if !NewLimiter(0.7692307692307693, 1).Allow() {
		t.Fatal("expected true")
	}
}

func TestSimultaneousRequests(t *testing.T) {
	const (
		limit       = 1
		burst       = 5
		numRequests = 15
	)
	var (
		wg    sync.WaitGroup
		numOK = uint32(0)
	)

	// Very slow replenishing bucket.
	lim := NewLimiter(limit, burst)

	// Tries to take a token, atomically updates the counter and decreases the wait
	// group counter.
	f := func() {
		defer wg.Done()
		if ok := lim.Allow(); ok {
			atomic.AddUint32(&numOK, 1)
		}
	}

	wg.Add(numRequests)
	for i := 0; i < numRequests; i++ {
		go f()
	}
	wg.Wait()
	if numOK != burst {
		t.Errorf("numOK = %d, want %d", numOK, burst)
	}
}

func TestLongRunningQPS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	if runtime.GOOS == "openbsd" {
		t.Skip("low resolution time.Sleep invalidates test (golang.org/issue/14183)")
		return
	}

	// The test runs for a few seconds executing many requests and then checks
	// that overall number of requests is reasonable.
	const (
		limit = 100
		burst = 100
	)
	var numOK = int32(0)

	lim := NewLimiter(limit, burst)

	var wg sync.WaitGroup
	f := func() {
		if ok := lim.Allow(); ok {
			atomic.AddInt32(&numOK, 1)
		}
		wg.Done()
	}

	// This will still offer ~500 requests per second,
	// but won't consume outrageous amount of CPU.
	start := time.Now()
	end := start.Add(5 * time.Second)
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for now := range ticker.C {
		if now.After(end) {
			break
		}
		wg.Add(1)
		go f()
	}
	wg.Wait()
	elapsed := time.Since(start)
	ideal := burst + (limit * float64(elapsed) / float64(time.Second))

	// We should never get more requests than allowed.
	if want := int32(ideal + 1); numOK > want {
		t.Errorf("numOK = %d, want %d (ideal %f)", numOK, want, ideal)
	}
	// We should get very close to the number of requests allowed.
	if want := int32(0.995 * ideal); numOK < want {
		t.Errorf("numOK = %d, want %d (ideal %f)", numOK, want, ideal)
	}
}

type request struct {
	t   time.Time
	n   int
	act time.Time
	ok  bool
}

// dFromDuration converts a duration to a multiple of the global constant d
func dFromDuration(dur time.Duration) int {
	// Adding a millisecond to be swallowed by the integer division
	// because we don't care about small inaccuracies
	return int((dur + time.Millisecond) / d)
}

// dSince returns multiples of d since t0
func dSince(t mono.Time) int {
	return dFromDuration(t.Sub(t0))
}

type wait struct {
	name   string
	ctx    context.Context
	n      int
	delay  int // in multiples of d
	nilErr bool
}

func BenchmarkAllowN(b *testing.B) {
	lim := NewLimiter(Every(1*time.Second), 1)
	now := mono.Now()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			lim.allow(now)
		}
	})
}

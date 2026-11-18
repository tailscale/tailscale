// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// This is a modified, simplified version of code from golang.org/x/time/rate.

// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rate

import (
	"math"
	"math/rand/v2"
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
	for range numRequests {
		go f()
	}
	wg.Wait()
	if numOK != burst {
		t.Errorf("numOK = %d, want %d", numOK, burst)
	}
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

// TestAllowFastPath checks that allow's lock-free denials (see
// [Limiter.next]) decide the same as the token bucket alone would,
// including when callers' timestamps arrive out of order.
func TestAllowFastPath(t *testing.T) {
	for _, tc := range []struct {
		limit Limit
		burst int
	}{
		{Every(10 * time.Second), 3},
		{Every(time.Millisecond), 10},
		{Every(time.Second), 1},
		{1e6, 5},
	} {
		lim := NewLimiter(tc.limit, tc.burst)
		// The bucket alone, as allow is without the fast path.
		tokens, last := 0.0, mono.Time(0)
		ref := func(now mono.Time) bool {
			elapsed := max(now.Sub(last), 0)
			tok := math.Min(tokens+float64(tc.limit)*elapsed.Seconds(), float64(tc.burst)) - 1
			if tok < 0 {
				return false
			}
			tokens, last = tok, now
			return true
		}
		rng := rand.New(rand.NewPCG(1, 2))
		now := mono.Time(0)
		allowed := 0
		for i := range 100000 {
			// Events about 4x as often as the limit, on average.
			interval := float64(time.Second) / float64(tc.limit)
			now = now.Add(time.Duration(rng.Int64N(int64(interval / 2))))
			// Sometimes a caller that read the time earlier arrives late.
			at := now
			if rng.IntN(10) == 0 {
				at = now.Add(-time.Duration(rng.Int64N(int64(3 * interval))))
			}
			got, want := lim.allow(at), ref(at)
			if got != want {
				t.Fatalf("limit %v burst %d: event %d at %v: allow = %v, want %v", tc.limit, tc.burst, i, at, got, want)
			}
			if got {
				allowed++
			}
		}
		if allowed == 0 {
			t.Errorf("limit %v burst %d: nothing allowed", tc.limit, tc.burst)
		}
	}
}

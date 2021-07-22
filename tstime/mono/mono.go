// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package mono provides fast monotonic time.
package mono

import (
	"fmt"
	"sync/atomic"
	"time"
	_ "unsafe" // for go:linkname
)

// Time is the number of nanoseconds elapsed since an unspecified reference start time.
type Time int64

// Now returns the current monotonic time.
func Now() Time { return Time(now()) }

// Since returns the time elapsed since t.
func Since(t Time) time.Duration {
	return time.Duration(now() - int64(t))
}

// Sub returns t-n, the duration from n to t.
func (t Time) Sub(n Time) time.Duration {
	return time.Duration(t - n)
}

// Add returns t+d.
func (t Time) Add(d time.Duration) Time {
	return t + Time(d)
}

// After reports t > n, whether t is after n.
func (t Time) After(n Time) bool {
	return t > n
}

// After reports t < n, whether t is before n.
func (t Time) Before(n Time) bool {
	return t < n
}

// IsZero reports whether t == 0.
func (t Time) IsZero() bool {
	return t == 0
}

// StoreAtomic does an atomic store *t = new.
func (t *Time) StoreAtomic(new Time) {
	atomic.StoreInt64((*int64)(t), int64(new))
}

// LoadAtomic does an atomic load *t.
func (t *Time) LoadAtomic() Time {
	return Time(atomic.LoadInt64((*int64)(t)))
}

//go:linkname now runtime.nanotime1
func now() int64

// baseWall and baseMono are a pair of almost-identical times used to correlate a Time with a wall time.
var (
	baseWall time.Time
	baseMono Time
)

func init() {
	baseWall = time.Now()
	baseMono = Now()
}

// String prints t, including an estimated equivalent wall clock.
// This is best-effort only, for rough debugging purposes only.
// Since it is a monotonic time, it can vary from the actual wall clock by arbitrary amounts.
// Even in the best of circumstances, it may vary by a few milliseconds.
func (t Time) String() string {
	return fmt.Sprintf("mono.Time(ns=%d, estimated wall=%v)", int64(t), baseWall.Add(t.Sub(baseMono)).Truncate(0))
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mono provides fast monotonic time.
// On most platforms, mono.Now is about 2x faster than time.Now.
// However, time.Now is really fast, and nicer to use.
//
// For almost all purposes, you should use time.Now.
//
// Package mono exists because we get the current time multiple
// times per network packet, at which point it makes a
// measurable difference.
package mono

import (
	"fmt"
	"sync/atomic"
	"time"
)

// Time is the number of nanoseconds elapsed since an unspecified reference start time.
type Time int64

// Now returns the current monotonic time.
func Now() Time {
	// On a newly started machine, the monotonic clock might be very near zero.
	// Thus mono.Time(0).Before(mono.Now.Add(-time.Minute)) might yield true.
	// The corresponding package time expression never does, if the wall clock is correct.
	// Preserve this correspondence by increasing the "base" monotonic clock by a fair amount.
	const baseOffset int64 = 1 << 55 // approximately 10,000 hours in nanoseconds
	return Time(int64(time.Since(baseWall)) + baseOffset)
}

// Since returns the time elapsed since t.
func Since(t Time) time.Duration {
	return time.Duration(Now() - t)
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

// Before reports t < n, whether t is before n.
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
// Since t is a monotonic time, it can vary from the actual wall clock by arbitrary amounts.
// Even in the best of circumstances, it may vary by a few milliseconds.
func (t Time) String() string {
	return fmt.Sprintf("mono.Time(ns=%d, estimated wall=%v)", int64(t), baseWall.Add(t.Sub(baseMono)).Truncate(0))
}

// WallTime returns an approximate wall time that corresponded to t.
func (t Time) WallTime() time.Time {
	if !t.IsZero() {
		return baseWall.Add(t.Sub(baseMono)).Truncate(0)
	}
	return time.Time{}
}

// MarshalJSON formats t for JSON as if it were a time.Time.
// We format Time this way for backwards-compatibility.
// Time does not survive a MarshalJSON/UnmarshalJSON round trip unchanged
// across different invocations of the Go process. This is best-effort only.
// Since t is a monotonic time, it can vary from the actual wall clock by arbitrary amounts.
// Even in the best of circumstances, it may vary by a few milliseconds.
func (t Time) MarshalJSON() ([]byte, error) {
	tt := t.WallTime()
	return tt.MarshalJSON()
}

// UnmarshalJSON sets t according to data.
// Time does not survive a MarshalJSON/UnmarshalJSON round trip unchanged
// across different invocations of the Go process. This is best-effort only.
func (t *Time) UnmarshalJSON(data []byte) error {
	var tt time.Time
	err := tt.UnmarshalJSON(data)
	if err != nil {
		return err
	}
	if tt.IsZero() {
		*t = 0
		return nil
	}
	*t = baseMono.Add(tt.Sub(baseWall))
	return nil
}

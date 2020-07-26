// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tstime defines Tailscale-specific time utilities.
package tstime

import (
	"context"
	"math/bits"
	"sync/atomic"
	"time"
)

// Time is an interface to all things that deal with the current time,
// and the passage of time. It's meant to be used as a replacement for
// the functions of the same name in the `time` and `context`
// packages, so that different implementations of time can be swapped
// in.
type Time interface {
	// After is like time.After.
	After(time.Duration) <-chan time.Time
	// Sleep is like time.Sleep.
	Sleep(time.Duration)
	// Tick is like time.Tick. TODO(danderson) remove? It leaks
	// goroutines and requires shutting up the linter, and we probably
	// shouldn't use it?...
	Tick(time.Duration) <-chan time.Time

	// Since is like time.Since.
	Since(time.Time) time.Duration
	// Until is like time.Until.
	Until(time.Time) time.Duration

	// NewTicker is like time.NewTicker.
	NewTicker(time.Duration) *time.Ticker

	// Now is like time.Now
	Now() time.Time

	// AfterFunc is like time.AfterFunc.
	AfterFunc(time.Duration, func()) *Timer
	// NewTimer is like time.NewTimer.
	NewTimer(time.Duration) *Timer

	// WithTimeout is like context.WithTimeout.
	WithTimeout(context.Context, time.Duration) (context.Context, context.CancelFunc)
	// WithDeadline is like context.WithDeadline.
	WithDeadline(context.Context, time.Time) (context.Context, context.CancelFunc)
}

// Timer wraps a time.Timer and makes its Reset function integrate
// with a custom Time implementation, rather than hardcode stdlib's.
type Timer struct {
	timer  *time.Timer
	adjust func(time.Duration) time.Duration
}

func (t *Timer) Reset(d time.Duration) bool {
	return t.timer.Reset(t.adjust(d))
}

func (t *Timer) Stop() bool {
	return t.timer.Stop()
}

// Std is a Time implementation that uses standard library
// functions. With this implementation, time works as you'd normally
// expect.
type Std struct{}

// After is like time.After.
func (Std) After(d time.Duration) <-chan time.Time { return time.After(d) }

// After is like time.Sleep.
func (Std) Sleep(d time.Duration) { time.Sleep(d) }

// After is like time.Since.
func (Std) Since(t time.Time) time.Duration { return time.Since(t) }

// After is like time.Until.
func (Std) Until(t time.Time) time.Duration { return time.Until(t) }

// After is like time.NewTicker.
func (Std) NewTicker(d time.Duration) *time.Ticker { return time.NewTicker(d) }

// After is like time.Now.
func (Std) Now() time.Time                           { return time.Now() }
func durationIdentity(d time.Duration) time.Duration { return d }

// After is like time.AfterFunc.
func (s Std) AfterFunc(d time.Duration, f func()) *Timer {
	return &Timer{time.AfterFunc(d, f), durationIdentity}
}

// After is like time.NewTimer.
func (s Std) NewTimer(d time.Duration) *Timer { return &Timer{time.NewTimer(d), durationIdentity} }

// After is like context.WithTimeout.
func (Std) WithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}

// After is like context.WithDeadline.
func (Std) WithDeadline(ctx context.Context, t time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(ctx, t)
}

// Tick is like time.Tick.
func (Std) Tick(d time.Duration) <-chan time.Time {
	//lint:ignore SA1015 implementing an API
	return time.Tick(d)
}

// Virtual is a Time implementation that runs faster or slower than
// wall clock time, but keeps ratios the same.
type Virtual struct {
	// Second is how long a virtual second actually takes in wall
	// clock time. That is, if you virtual.Sleep(time.Second), this is
	// how long you'll actually sleep.
	Second time.Duration

	// first is the first value of time.Now seen by this virtual
	// instance. It's used as the origin point for virtual time.Time
	// values when scaling them to/from wall clock time.
	first int64 // nanoseconds since Epoch, accessed atomically.
}

func (vt *Virtual) init() {
	atomic.CompareAndSwapInt64(&vt.first, 0, time.Now().UnixNano())
}

// mulDiv implements v*mul/div using 128-bit integer math, to avoid
// overflows and losses of precision.
func mulDiv(v, mul, div time.Duration) time.Duration {
	neg := v < 0
	if neg {
		v = -v
	}

	hi, lo := bits.Mul64(uint64(v), uint64(mul))
	quo, _ := bits.Div64(hi, lo, uint64(div))

	ret := time.Duration(quo)
	if neg {
		ret = -ret
	}
	return ret
}

// virtualToWallDuration converts a time.Duration from the virtual
// reference frame to the wall clock reference frame. This is the
// transform that takes place to convert
// virtual.Sleep(virtualDuration) into time.Sleep(realDuration), for
// example.
func (vt *Virtual) virtualToWallDuration(d time.Duration) time.Duration {
	return mulDiv(d, vt.Second, time.Second)
}

// wallToVirtualDuration converts a time.Duration from the wall clock
// reference frame to the virtual reference frame.
func (vt *Virtual) wallToVirtualDuration(d time.Duration) time.Duration {
	return mulDiv(d, time.Second, vt.Second)
}

func (vt *Virtual) virtualToWallTime(t time.Time) time.Time {
	vt.init()
	wt := time.Unix(0, atomic.LoadInt64(&vt.first)).In(t.Location())
	return wt.Add(vt.virtualToWallDuration(t.Sub(wt)))
}
func (vt *Virtual) wallToVirtualTime(t time.Time) time.Time {
	vt.init()
	ret := time.Unix(0, atomic.LoadInt64(&vt.first)).In(t.Location())
	return ret.Add(vt.wallToVirtualDuration(t.Sub(ret)))
}

// After is like time.After.
func (vt *Virtual) After(d time.Duration) <-chan time.Time {
	return time.After(vt.virtualToWallDuration(d))
}

// Sleep is like time.Sleep.
func (vt *Virtual) Sleep(d time.Duration) {
	time.Sleep(vt.virtualToWallDuration(d))
}

// Tick is like time.Tick.
func (vt *Virtual) Tick(d time.Duration) <-chan time.Time {
	//lint:ignore SA1015 implementing an API
	return time.Tick(vt.virtualToWallDuration(d))
}

// Since is like time.Since.
func (vt *Virtual) Since(t time.Time) time.Duration {
	return vt.wallToVirtualDuration(time.Since(vt.virtualToWallTime(t)))
}

// Until is like time.Until.
func (vt *Virtual) Until(t time.Time) time.Duration {
	return vt.wallToVirtualDuration(time.Until(vt.virtualToWallTime(t)))
}

// NewTicker is like time.NewTicker.
func (vt *Virtual) NewTicker(d time.Duration) *time.Ticker {
	return time.NewTicker(vt.virtualToWallDuration(d))
}

// Now is like time.Now.
func (vt *Virtual) Now() time.Time {
	vt.init() // to make realNow after the start of our universe
	realNow := time.Now().Round(0)
	return vt.wallToVirtualTime(realNow)
}

// AfterFunc is like time.AfterFunc.
func (vt *Virtual) AfterFunc(d time.Duration, f func()) *Timer {
	return &Timer{
		timer:  time.AfterFunc(vt.virtualToWallDuration(d), f),
		adjust: vt.virtualToWallDuration,
	}
}

// NewTimer is like time.NewTimer.
func (vt *Virtual) NewTimer(d time.Duration) *Timer {
	return &Timer{
		timer:  time.NewTimer(vt.virtualToWallDuration(d)),
		adjust: vt.virtualToWallDuration,
	}
}

// WithTimeout is like context.WithTimeout.
func (vt *Virtual) WithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, vt.virtualToWallDuration(d))
	return virtualContext{ctx, vt}, cancel
}

// WithDeadline is like context.WithDeadline.
func (vt *Virtual) WithDeadline(ctx context.Context, t time.Time) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithDeadline(ctx, vt.virtualToWallTime(t))
	return virtualContext{ctx, vt}, cancel
}

// virtualContext is a context.Context that presents the correct
// virtual time in its Deadline() call.
type virtualContext struct {
	context.Context
	vt *Virtual
}

// Deadline returns the time when work done on behalf of this context
// should be canceled. Deadline returns ok==false when no deadline is
// set. Successive calls to Deadline return the same results.
func (dc virtualContext) Deadline() (time.Time, bool) {
	t, ok := dc.Context.Deadline()
	return dc.vt.wallToVirtualTime(t), ok
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package logger

import (
	"time"
)

// tokenBucket is a simple token bucket style rate limiter.

// It's similar in function to golang.org/x/time/rate.Limiter, which we
// can't use because:
//   - It doesn't give access to the number of accumulated tokens, which we
//     need for implementing hysteresis;
//   - It doesn't let us provide our own time function, which we need for
//     implementing proper unit tests.
//
// rate.Limiter is also much more complex than necessary, but that wouldn't
// be enough to disqualify it on its own.
//
// Unlike rate.Limiter, this token bucket does not attempt to
// do any locking of its own. Don't try to access it reentrantly.
// That's fine inside this types/logger package because we already have
// locking at a higher level.
type tokenBucket struct {
	remaining int
	max       int
	tick      time.Duration
	t         time.Time
}

func newTokenBucket(tick time.Duration, max int, now time.Time) *tokenBucket {
	return &tokenBucket{max, max, tick, now}
}

func (tb *tokenBucket) Get() bool {
	if tb.remaining > 0 {
		tb.remaining--
		return true
	}
	return false
}

func (tb *tokenBucket) Refund(n int) {
	b := tb.remaining + n
	if b > tb.max {
		tb.remaining = tb.max
	} else {
		tb.remaining = b
	}
}

func (tb *tokenBucket) AdvanceTo(t time.Time) {
	diff := t.Sub(tb.t)

	// only use up whole ticks. The remainder will be used up
	// next time.
	ticks := int(diff / tb.tick)
	tb.t = tb.t.Add(time.Duration(ticks) * tb.tick)

	tb.Refund(ticks)
}

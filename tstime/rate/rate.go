// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This is a modified, simplified version of code from golang.org/x/time/rate.

// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rate provides a rate limiter.
package rate

import (
	"sync"
	"time"

	"tailscale.com/tstime/mono"
)

// Limit defines the maximum frequency of some events.
// Limit is represented as number of events per second.
// A zero Limit is invalid.
type Limit float64

// Every converts a minimum time interval between events to a Limit.
func Every(interval time.Duration) Limit {
	if interval <= 0 {
		panic("invalid interval")
	}
	return 1 / Limit(interval.Seconds())
}

// A Limiter controls how frequently events are allowed to happen.
// It implements a [token bucket] of a particular size b,
// initially full and refilled at rate r tokens per second.
// Informally, in any large enough time interval,
// the Limiter limits the rate to r tokens per second,
// with a maximum burst size of b events.
// Use NewLimiter to create non-zero Limiters.
//
// [token bucket]: https://en.wikipedia.org/wiki/Token_bucket
type Limiter struct {
	limit  Limit
	burst  float64
	mu     sync.Mutex // protects following fields
	tokens float64    // number of tokens currently in bucket
	last   mono.Time  // the last time the limiter's tokens field was updated
}

// NewLimiter returns a new Limiter that allows events up to rate r and permits
// bursts of at most b tokens.
func NewLimiter(r Limit, b int) *Limiter {
	if b < 1 {
		panic("bad burst, must be at least 1")
	}
	return &Limiter{limit: r, burst: float64(b)}
}

// Allow reports whether an event may happen now.
func (lim *Limiter) Allow() bool {
	return lim.allow(mono.Now())
}

func (lim *Limiter) allow(now mono.Time) bool {
	lim.mu.Lock()
	defer lim.mu.Unlock()

	// If time has moved backwards, look around awkwardly and pretend nothing happened.
	if now.Before(lim.last) {
		lim.last = now
	}

	// Calculate the new number of tokens available due to the passage of time.
	elapsed := now.Sub(lim.last)
	tokens := lim.tokens + float64(lim.limit)*elapsed.Seconds()
	if tokens > lim.burst {
		tokens = lim.burst
	}

	// Consume a token.
	tokens--

	// Update state.
	ok := tokens >= 0
	if ok {
		lim.last = now
		lim.tokens = tokens
	}
	return ok
}

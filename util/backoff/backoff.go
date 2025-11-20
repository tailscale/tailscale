// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package backoff provides a back-off timer type.
package backoff

import (
	"context"
	"math/rand/v2"
	"time"

	"tailscale.com/tstime"
	"tailscale.com/types/logger"
)

// Backoff tracks state the history of consecutive failures and sleeps
// an increasing amount of time, up to a provided limit.
type Backoff struct {
	n          int // number of consecutive failures
	maxBackoff time.Duration

	// Name is the name of this backoff timer, for logging purposes.
	name string
	// logf is the function used for log messages when backing off.
	logf logger.Logf

	// tstime.Clock.NewTimer is used instead time.NewTimer.
	Clock tstime.Clock

	// LogLongerThan sets the minimum time of a single backoff interval
	// before we mention it in the log.
	LogLongerThan time.Duration
}

// NewBackoff returns a new Backoff timer with the provided name (for logging), logger,
// and max backoff time. By default, all failures (calls to BackOff with a non-nil err)
// are logged unless the returned Backoff.LogLongerThan is adjusted.
func NewBackoff(name string, logf logger.Logf, maxBackoff time.Duration) *Backoff {
	return &Backoff{
		name:       name,
		logf:       logf,
		maxBackoff: maxBackoff,
		Clock:      tstime.StdClock{},
	}
}

// BackOff sleeps an increasing amount of time if err is non-nil while the
// context is active. It resets the backoff schedule once err is nil.
func (b *Backoff) BackOff(ctx context.Context, err error) {
	if err == nil {
		// No error. Reset number of consecutive failures.
		b.n = 0
		return
	}
	if ctx.Err() != nil {
		// Fast path.
		return
	}

	b.n++
	// n^2 backoff timer is a little smoother than the
	// common choice of 2^n.
	d := time.Duration(b.n*b.n) * 10 * time.Millisecond
	if d > b.maxBackoff {
		d = b.maxBackoff
	}
	// Randomize the delay between 0.5-1.5 x msec, in order
	// to prevent accidental "thundering herd" problems.
	d = time.Duration(float64(d) * (rand.Float64() + 0.5))

	if d >= b.LogLongerThan {
		b.logf("%s: [v1] backoff: %d msec", b.name, d.Milliseconds())
	}
	t, tChannel := b.Clock.NewTimer(d)
	select {
	case <-ctx.Done():
		t.Stop()
	case <-tChannel:
	}
}

// Reset resets the backoff schedule, equivalent to calling BackOff with a nil
// error.
func (b *Backoff) Reset() {
	b.n = 0
}

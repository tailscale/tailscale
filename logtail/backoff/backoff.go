// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package backoff

import (
	"context"
	"math/rand"
	"time"

	"tailscale.com/types/logger"
)

const MAX_BACKOFF_MSEC = 30000

type Backoff struct {
	n int
	// Name is the name of this backoff timer, for logging purposes.
	name string
	// logf is the function used for log messages when backing off.
	logf logger.Logf
	// NewTimer is the function that acts like time.NewTimer().
	// You can override this in unit tests.
	NewTimer func(d time.Duration) *time.Timer
	// LogLongerThan sets the minimum time of a single backoff interval
	// before we mention it in the log.
	LogLongerThan time.Duration
}

func NewBackoff(name string, logf logger.Logf) Backoff {
	return Backoff{
		name:     name,
		logf:     logf,
		NewTimer: time.NewTimer,
	}
}

func (b *Backoff) BackOff(ctx context.Context, err error) {
	if ctx.Err() == nil && err != nil {
		b.n++
		// n^2 backoff timer is a little smoother than the
		// common choice of 2^n.
		msec := b.n * b.n * 10
		if msec > MAX_BACKOFF_MSEC {
			msec = MAX_BACKOFF_MSEC
		}
		// Randomize the delay between 0.5-1.5 x msec, in order
		// to prevent accidental "thundering herd" problems.
		msec = rand.Intn(msec) + msec/2
		dur := time.Duration(msec) * time.Millisecond
		if dur >= b.LogLongerThan {
			b.logf("%s: backoff: %d msec\n", b.name, msec)
		}
		t := b.NewTimer(dur)
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
	} else {
		// not a regular error
		b.n = 0
	}
}

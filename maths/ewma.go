// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package maths contains additional mathematical functions or structures not
// found in the standard library.
package maths

import (
	"math"
	"time"
)

// EWMA is an exponentially weighted moving average supporting updates at
// irregular intervals with at most nanosecond resolution.
// The zero value will compute a half-life of 1 second.
// It is not safe for concurrent use.
// TODO(raggi): de-duplicate with tstime/rate.Value, which has a more complex
// and synchronized interface and does not provide direct access to the stable
// value.
type EWMA struct {
	value    float64 // current value of the average
	lastTime int64   // time of last update in unix nanos
	halfLife float64 // half-life in seconds
}

// NewEWMA creates a new EWMA with the specified half-life. If halfLifeSeconds
// is 0, it defaults to 1.
func NewEWMA(halfLifeSeconds float64) *EWMA {
	return &EWMA{
		halfLife: halfLifeSeconds,
	}
}

// Update adds a new sample to the average. If t is zero or precedes the last
// update, the update is ignored.
func (e *EWMA) Update(value float64, t time.Time) {
	if t.IsZero() {
		return
	}
	hl := e.halfLife
	if hl == 0 {
		hl = 1
	}
	tn := t.UnixNano()
	if e.lastTime == 0 {
		e.value = value
		e.lastTime = tn
		return
	}

	dt := (time.Duration(tn-e.lastTime) * time.Nanosecond).Seconds()
	if dt < 0 {
		// drop out of order updates
		return
	}

	// decay = 2^(-dt/halfLife)
	decay := math.Exp2(-dt / hl)
	e.value = e.value*decay + value*(1-decay)
	e.lastTime = tn
}

// Get returns the current value of the average
func (e *EWMA) Get() float64 {
	return e.value
}

// Reset clears the EWMA to its initial state
func (e *EWMA) Reset() {
	e.value = 0
	e.lastTime = 0
}

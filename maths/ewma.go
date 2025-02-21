// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ewma

import (
	"math"
	"time"
)

// EWMA is an exponentially weighted moving average supporting updates at
// irregular intervals with at most nanosecond resolution.
type EWMA struct {
	value    float64 // current value of the average
	lastTime int64   // time of last update in unix nanos
	halfLife float64 // half-life in seconds
}

// NewEWMA creates a new EWMA with the specified half-life
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
	decay := math.Exp2(-dt / e.halfLife)
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

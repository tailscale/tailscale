// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derp

import (
	"io/ioutil"
	"strconv"
	"strings"
	"time"
)

func readTxBytes(interfaceName string) (uint64, error) {
	v, err := ioutil.ReadFile("/sys/class/net/" + interfaceName + "/statistics/tx_bytes")
	if err != nil {
		return 0, err
	}
	tx, err := strconv.Atoi(strings.TrimSpace(string(v)))
	if err != nil {
		return 0, err
	}
	return uint64(tx), nil
}

type egressLimiter struct {
	interfaceName string
	limitBytesSec uint64 // the egress bytes/s we want to stay under.
	minBytesSec   uint64 // the minimum bytes/s rate limit.

	lastTxBytes uint64
	controlLoop limiterLoop
}

func newEgressLimiter(interfaceName string, limitBytesSec, minBytesSec uint64) (*egressLimiter, error) {
	initial, err := readTxBytes(interfaceName)
	if err != nil {
		return nil, err
	}

	return &egressLimiter{
		interfaceName: interfaceName,
		limitBytesSec: limitBytesSec,
		minBytesSec:   minBytesSec,
		lastTxBytes:   initial,
		controlLoop:   newLimiterLoop(limitBytesSec, time.Now()),
	}, err
}

// Limit returns the current rate limit value based on interface utilization.
func (e *egressLimiter) Limit() (uint64, error) {
	rx, err := readTxBytes(e.interfaceName)
	if err != nil {
		return 0, err
	}

	last := e.lastTxBytes
	e.lastTxBytes = rx

	limit := e.controlLoop.tick(uint64(rx)-last, time.Now())
	if limit < 0 || uint64(limit) < e.minBytesSec {
		limit = float64(e.minBytesSec)
	}
	if uint64(limit) > e.limitBytesSec {
		limit = float64(e.limitBytesSec)
	}
	return uint64(limit), nil
}

// PID loop values for the dynamic ratelimit.
// The wikipedia page on PID is recommended reading if you are not familiar
// with PID loops or open-loop control theory.
//
// Gain values are unitless, but operate on a feedback value in bytes
// and a setpoint value in bytes/s, and a time delta (dt) of seconds.
//
// These values are initial and should be tuned: These are just initial
// values based on first principles and vibin with pretty graphs.
const (
	// Proportional gain.
	// Given this represents a global ratelimit, the P term doesnt make a lot of
	// sense, as each clients contribution to link utilization is entirely
	// dependent on the client workload.
	//
	// For this reason, its set super low: Its expected the I term will do
	// most of the heavy lifting.
	limiterP float64 = 1.0 / 1024
	// Derivative gain.
	// This term reacts against 'trends', that is, the first derivative of
	// the feedback value. Think of it like a rapid-change damper.
	//
	// This isnt super important, so again we've set it fairly low.
	limiterD float64 = 0.003
	// Integral gain.
	//
	// This is where all the heavy lifting happens. Basically, we increase
	// the ratelimit (by limiterIP) when we have room to spare, and
	// decrease it once we exceed 4/5ths of the limit (by limiterIN).
	// The increase is linear to the error between feedback and the setpoint,
	// but clamped proportionate to the limit.
	//
	// The decrease term is stronger than the increase term, so we 'backoff
	// quickly' when we are approaching limits, but test the waters on
	// the other end cautiously.
	limiterIP float64 = 0.008
	limiterIN float64 = 0.3
)

// limiterLoop exposes a dynamic ratelimit, based on the egress rate
// of some interface. The PID loop tries to keep egress at 4/5 of the limit.
type limiterLoop struct {
	limitBytesSec uint64 // the egress bytes/s we want to stay under.

	integral   float64   // the integral sum at lastUpdate instant
	lastEgress uint64    // feedback value of previous iteration, bytes/s
	lastUpdate time.Time // instant at which last iteration occurred.
}

func newLimiterLoop(limitBytesSec uint64, now time.Time) limiterLoop {
	return limiterLoop{
		limitBytesSec: limitBytesSec * 4 / 5,
		lastUpdate:    now,
		lastEgress:    0,
		integral:      float64(limitBytesSec),
	}
}

// tick computes & returns the ratelimit value in bytes/s, computing
// the next iteration of the PID loop in the process.
func (l *limiterLoop) tick(egressBytesPerSec uint64, now time.Time) float64 {
	var (
		dt  = now.Sub(l.lastUpdate).Seconds()
		err = float64(l.limitBytesSec) - float64(egressBytesPerSec)
	)

	// Integral term.
	var iDelta float64
	if err > 0 {
		iDelta = err * dt * limiterIP
	} else {
		iDelta = err * dt * limiterIN
	}
	// Constrain integral sum change to a 20th of the setpoint per second.
	maxDelta := dt * float64(l.limitBytesSec) / 20
	if iDelta > maxDelta {
		iDelta = maxDelta
	} else if iDelta < -maxDelta {
		iDelta = -maxDelta
	}
	l.integral += iDelta
	// Constrain integral sum to prevent windup.
	if max := float64(l.limitBytesSec); l.integral > max {
		l.integral = max
	} else if l.integral < -max {
		l.integral = -max
	}

	// Derivative term.
	var d float64
	if dt > 0 {
		d = -(float64(egressBytesPerSec-l.lastEgress) / dt) * limiterD
	}
	// Proportional term.
	p := limiterP * err

	l.lastEgress = egressBytesPerSec
	l.lastUpdate = now
	output := p + l.integral + d
	// fmt.Printf("in=%d, out=%0.3f:   p=%0.2f d=%0.2f i=%0.2f\n", egressBytesPerSec, output, p, d, l.integral)
	return output
}

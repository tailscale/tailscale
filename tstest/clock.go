// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstest

import (
	"sync"
	"time"
)

// ClockOpts is used to configure the initial settings for a Clock. Once the
// settings are configured as desired, call NewClock to get the resulting Clock.
type ClockOpts struct {
	// Start is the starting time for the Clock. When FollowRealTime is false,
	// Start is also the value that will be returned by the first call
	// to Clock.Now.
	Start time.Time
	// Step is the amount of time the Clock will advance whenever Clock.Now is
	// called. If set to zero, the Clock will only advance when Clock.Advance is
	// called and/or if FollowRealTime is true.
	//
	// FollowRealTime and Step cannot be enabled at the same time.
	Step time.Duration

	// TimerChannelSize configures the maximum buffered ticks that are
	// permitted in the channel of any Timer and Ticker created by this Clock.
	// The special value 0 means to use the default of 1. The buffer may need to
	// be increased if time is advanced by more than a single tick and proper
	// functioning of the test requires that the ticks are not lost.
	TimerChannelSize int

	// FollowRealTime makes the simulated time increment along with real time.
	// It is a compromise between determinism and the difficulty of explicitly
	// managing the simulated time via Step or Clock.Advance. When
	// FollowRealTime is set, calls to Now() and PeekNow() will add the
	// elapsed real-world time to the simulated time.
	//
	// FollowRealTime and Step cannot be enabled at the same time.
	FollowRealTime bool
}

// NewClock creates a Clock with the specified settings. To create a
// Clock with only the default settings, new(Clock) is equivalent, except that
// the start time will not be computed until one of the receivers is called.
func NewClock(co ClockOpts) *Clock {
	if co.TimerChannelSize != 0 || co.FollowRealTime {
		panic("TimerChannelSize and FollowRealTime are not implemented yet")
	}

	clock := &Clock{
		Start: co.Start,
		Step:  co.Step,
	}
	clock.Lock()
	defer clock.Unlock()
	clock.initLocked()

	return clock
}

// Clock is a testing clock that advances every time its Now method is
// called, beginning at Start.
//
// The zero value starts virtual time at an arbitrary value recorded
// in Start on the first call to Now, and time never advances.
type Clock struct {
	// Start is the first value returned by Now.
	Start time.Time
	// Step is how much to advance with each Now call.
	Step time.Duration
	// Present is the time that the next Now call will receive.
	Present time.Time

	sync.Mutex
}

// Now returns the virtual clock's current time, and advances it
// according to its step configuration.
func (c *Clock) Now() time.Time {
	c.Lock()
	defer c.Unlock()
	c.initLocked()
	step := c.Step
	ret := c.Present
	c.Present = c.Present.Add(step)
	return ret
}

func (c *Clock) Advance(d time.Duration) {
	c.Lock()
	defer c.Unlock()
	c.initLocked()
	c.Present = c.Present.Add(d)
}

func (c *Clock) initLocked() {
	if c.Start.IsZero() {
		c.Start = time.Now()
	}
	if c.Present.Before(c.Start) {
		c.Present = c.Start
	}
}

// Reset rewinds the virtual clock to its start time.
func (c *Clock) Reset() {
	c.Lock()
	defer c.Unlock()
	c.Present = c.Start
}

// GetStart returns the initial simulated time when this Clock was created.
func (c *Clock) GetStart() time.Time {
	c.Lock()
	defer c.Unlock()
	c.initLocked()
	return c.Start
}

// GetStep returns the amount that simulated time advances on every call to Now.
func (c *Clock) GetStep() time.Duration {
	c.Lock()
	defer c.Unlock()
	c.initLocked()
	return c.Step
}

// SetStep updates the amount that simulated time advances on every call to Now.
func (c *Clock) SetStep(d time.Duration) {
	c.Lock()
	defer c.Unlock()
	c.initLocked()
	c.Step = d
}

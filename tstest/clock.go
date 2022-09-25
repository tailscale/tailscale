// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstest

import (
	"sync"
	"time"
)

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

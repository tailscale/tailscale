// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testy

import "time"

// Clock is a testing clock that advances by 1 second every time its
// Now method is called, beginning at Start.
//
// The zero value starts virtual time at an arbitrary value recorded
// in Start on the first call to Now, and increments by one second
// between calls to Now.
type Clock struct {
	Start time.Time     // First value returned by Now().
	Step  time.Duration // How much time advances with each Now() call.

	Present time.Time // Time that the next Now() call will receive.
}

// Now returns the virtual clock's current time, and avances it
// according to its step configuration.
func (c *Clock) Now() time.Time {
	if c.Start.IsZero() && c.Step == 0 {
		c.Start = time.Now()
		c.Step = time.Second
		c.Present = c.Start
	}
	if c.Present.IsZero() {
		c.Present = c.Start
	}
	ret := c.Present
	c.Present = c.Present.Add(c.Step)
	return ret
}

// Advance adds d to the current virtual time.
func (c *Clock) Advance(d time.Duration) {
	c.Present = c.Present.Add(d)
}

// Reset rewinds the virtual clock to its start time.
func (c *Clock) Reset() {
	c.Present = c.Start
}

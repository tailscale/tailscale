// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package coalescedop provides a mechanism to serialize and coalesce
// calls to a function. At most one call is in flight at a time, and
// if additional calls are requested while one is running, exactly one
// more execution is scheduled after the current one completes.
//
// Unlike [singleflight.Group], which deduplicates concurrent callers
// onto a single in-flight call, [CoalescedOp] ensures that a new
// execution occurs after the current one finishes, so changes that
// happened during the in-flight call are picked up by the next run.
package coalescedop

import "sync"

// CoalescedOp serializes and coalesces calls to a function.
// At most one call is in flight at a time. If additional calls
// are requested while one is running, exactly one more execution
// is scheduled (not one per request).
//
// The zero value is not valid; use [New].
type CoalescedOp struct {
	mu      sync.Mutex
	fn      func()
	running bool
	pending bool
}

// New returns a CoalescedOp that calls fn.
func New(fn func()) *CoalescedOp {
	return &CoalescedOp{fn: fn}
}

// Do requests that the operation be run. If no execution is in
// progress, a new goroutine is started to run the function. If an
// execution is already in progress, the function will be run exactly
// once more after the current execution completes.
//
// Do never blocks.
func (c *CoalescedOp) Do() {
	c.mu.Lock()
	if c.running {
		c.pending = true
		c.mu.Unlock()
		return
	}
	c.running = true
	c.mu.Unlock()
	go c.run()
}

func (c *CoalescedOp) run() {
	for {
		c.fn()

		c.mu.Lock()
		if !c.pending {
			c.running = false
			c.mu.Unlock()
			return
		}
		c.pending = false
		c.mu.Unlock()
	}
}

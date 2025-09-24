// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import "tailscale.com/syncs"

// A Monitor monitors the execution of a goroutine processing events from a
// [Client], allowing the caller to block until it is complete. The zero value
// of m is valid; its Close and Wait methods return immediately, and its Done
// method returns an already-closed channel.
type Monitor struct {
	// These fields are immutable after initialization
	cli  *Client
	done <-chan struct{}
}

// Close closes the client associated with m and blocks until the processing
// goroutine is complete.
func (m Monitor) Close() {
	if m.cli == nil {
		return
	}
	m.cli.Close()
	<-m.done
}

// Wait blocks until the goroutine monitored by m has finished executing, but
// does not close the associated client.  It is safe to call Wait repeatedly,
// and from multiple concurrent goroutines.
func (m Monitor) Wait() {
	if m.done == nil {
		return
	}
	<-m.done
}

// Done returns a channel that is closed when the monitored goroutine has
// finished executing.
func (m Monitor) Done() <-chan struct{} {
	if m.done == nil {
		return syncs.ClosedChan()
	}
	return m.done
}

// Monitor executes f in a new goroutine attended by a [Monitor].  The caller
// is responsible for waiting for the goroutine to complete, by calling either
// [Monitor.Close] or [Monitor.Wait].
func (c *Client) Monitor(f func(*Client)) Monitor {
	done := make(chan struct{})
	go func() { defer close(done); f(c) }()
	return Monitor{cli: c, done: done}
}

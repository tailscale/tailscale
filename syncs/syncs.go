// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package syncs contains addition sync types.
package syncs

import "sync/atomic"

// ClosedChan returns a channel that's already closed.
func ClosedChan() <-chan struct{} { return closedChan }

var closedChan = initClosedChan()

func initClosedChan() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// WaitGroupChan is like a sync.WaitGroup, but has a chan that closes
// on completion that you can wait on. (This, you can only use the
// value once)
// Also, its zero value is not usable. Use the constructor.
type WaitGroupChan struct {
	n    int64         // atomic
	done chan struct{} // closed on transition to zero
}

// NewWaitGroupChan returns a new single-use WaitGroupChan.
func NewWaitGroupChan() *WaitGroupChan {
	return &WaitGroupChan{done: make(chan struct{})}
}

// DoneChan returns a channel that's closed on completion.
func (c *WaitGroupChan) DoneChan() <-chan struct{} { return c.done }

// Add adds delta, which may be negative, to the WaitGroupChan
// counter. If the counter becomes zero, all goroutines blocked on
// Wait or the Done chan are released. If the counter goes negative,
// Add panics.
//
// Note that calls with a positive delta that occur when the counter
// is zero must happen before a Wait. Calls with a negative delta, or
// calls with a positive delta that start when the counter is greater
// than zero, may happen at any time. Typically this means the calls
// to Add should execute before the statement creating the goroutine
// or other event to be waited for.
func (c *WaitGroupChan) Add(delta int) {
	n := atomic.AddInt64(&c.n, int64(delta))
	if n == 0 {
		close(c.done)
	}
}

// Decr decrements the WaitGroup counter by one.
//
// (It is like sync.WaitGroup's Done method, but we don't use Done in
// this type, because it's ambiguous between Context.Done and
// WaitGroup.Done. So we use DoneChan and Decr instead.)
func (wg *WaitGroupChan) Decr() {
	wg.Add(-1)
}

// Wait blocks until the WaitGroupChan counter is zero.
func (wg *WaitGroupChan) Wait() { <-wg.done }

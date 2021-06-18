// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package syncs contains additional sync types and functionality.
package syncs

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

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
func (wg *WaitGroupChan) DoneChan() <-chan struct{} { return wg.done }

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
func (wg *WaitGroupChan) Add(delta int) {
	n := atomic.AddInt64(&wg.n, int64(delta))
	if n == 0 {
		close(wg.done)
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

// AtomicBool is an atomic boolean.
type AtomicBool int32

func (b *AtomicBool) Set(v bool) {
	var n int32
	if v {
		n = 1
	}
	atomic.StoreInt32((*int32)(b), n)
}

func (b *AtomicBool) Get() bool {
	return atomic.LoadInt32((*int32)(b)) != 0
}

// AtomicUint32 is an atomic uint32.
type AtomicUint32 uint32

func (b *AtomicUint32) Set(v uint32) {
	atomic.StoreUint32((*uint32)(b), v)
}

func (b *AtomicUint32) Get() uint32 {
	return atomic.LoadUint32((*uint32)(b))
}

// Semaphore is a counting semaphore.
//
// Use NewSemaphore to create one.
type Semaphore struct {
	c chan struct{}
}

// NewSemaphore returns a semaphore with resource count n.
func NewSemaphore(n int) Semaphore {
	return Semaphore{c: make(chan struct{}, n)}
}

// Acquire blocks until a resource is acquired.
func (s Semaphore) Acquire() {
	s.c <- struct{}{}
}

// AcquireContext reports whether the resource was acquired before the ctx was done.
func (s Semaphore) AcquireContext(ctx context.Context) bool {
	select {
	case s.c <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// TryAcquire reports, without blocking, whether the resource was acquired.
func (s Semaphore) TryAcquire() bool {
	select {
	case s.c <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release releases a resource.
func (s Semaphore) Release() {
	<-s.c
}

// WaitableResult allows for blocking on a repeated, fallible operation until it completes,
// and getting the result.
type WaitableResult struct {
	// sync.Cond.L guards all the fields below, and is used to wait until completed is true.
	cond *sync.Cond
	// Completed is set after the first operation has completed, and should be used in conjunction
	// with `cond` above in order to block.
	completed bool

	result bool  // result is whether or not the most recent operation succeeded or not.
	err    error // err indicates the most recent error during the operation.

	// sawTime is the last time this result was updated.
	sawTime time.Time
}

func NewWaitableResult() WaitableResult {
	return WaitableResult{
		cond: &sync.Cond{
			L: &sync.Mutex{},
		},
	}
}

// Get blocks until an operation completes, then returns true if it was a success.
// Otherwise, it returns returns false, with a possible error.
func (wr *WaitableResult) Get() (bool, error) {
	wr.cond.L.Lock()
	defer wr.cond.L.Unlock()
	for !wr.completed {
		wr.cond.Wait()
	}
	return wr.result, wr.err
}

// Current returns the current state of the result without blocking, regardless of whether or
// not it has completed, as well as the completion time of the operation.
func (wr *WaitableResult) Peek() (time.Time, bool, error) {
	wr.cond.L.Lock()
	defer wr.cond.L.Unlock()
	return wr.sawTime, wr.result, wr.err
}

// Set should be called when an operation has completed. It will unblock any items waiting for
// the completed operation, and overwrite previous the results of previous operations.
func (wr *WaitableResult) Set(result bool, err error) {
	saw := time.Now()
	wr.cond.L.Lock()
	wr.sawTime = saw
	wr.completed = true
	wr.err = err
	wr.result = result
	wr.cond.L.Unlock()

	wr.cond.Broadcast()
}

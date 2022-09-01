// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package syncs contains additional sync types and functionality.
package syncs

import (
	"context"
	"sync/atomic"
)

// ClosedChan returns a channel that's already closed.
func ClosedChan() <-chan struct{} { return closedChan }

var closedChan = initClosedChan()

func initClosedChan() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// AtomicValue is the generic version of atomic.Value.
type AtomicValue[T any] struct {
	v atomic.Value
}

// Load returns the value set by the most recent Store.
// It returns the zero value for T if the value is empty.
func (v *AtomicValue[T]) Load() T {
	x, _ := v.LoadOk()
	return x
}

// LoadOk is like Load but returns a boolean indicating whether the value was
// loaded.
func (v *AtomicValue[T]) LoadOk() (_ T, ok bool) {
	x := v.v.Load()
	if x != nil {
		return x.(T), true
	}
	var zero T
	return zero, false
}

// Store sets the value of the Value to x.
func (v *AtomicValue[T]) Store(x T) {
	v.v.Store(x)
}

// Swap stores new into Value and returns the previous value.
// It returns the zero value for T if the value is empty.
func (v *AtomicValue[T]) Swap(x T) (old T) {
	oldV := v.v.Swap(x)
	if oldV != nil {
		return oldV.(T)
	}
	return old
}

// CompareAndSwap executes the compare-and-swap operation for the Value.
func (v *AtomicValue[T]) CompareAndSwap(oldV, newV T) (swapped bool) {
	return v.v.CompareAndSwap(oldV, newV)
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

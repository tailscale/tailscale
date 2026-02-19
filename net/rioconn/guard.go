// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"sync"
	"sync/atomic"
)

// guard prevents new operations from starting after Close
// while allowing in-flight operations to complete.
type guard struct {
	state     atomic.Int64
	done      chan struct{}
	closeOnce sync.Once
}

const (
	// state layout:
	//   bit 62: closed flag (1 == Close called)
	//   bits 0–61: in-flight operation count
	//
	// We avoid using bit 63 (the sign bit) so that valid states remain
	// non-negative and the counter has a large positive range. guardCountMask
	// isolates the counter bits and is used to detect unbalanced Release calls
	// or counter overflow (which would wrap into the closed bit).
	guardClosedBit = int64(1) << 62
	guardCountMask = guardClosedBit - 1
)

func newGuard() *guard {
	return &guard{done: make(chan struct{})}
}

// Acquire attempts to acquire a lease for an operation.
//
// If it reports true, the caller may proceed and must call
// [guard.Release] when done. Otherwise, it must not proceed.
//
// Acquire fails if [guard.Close] has already been called.
func (g *guard) Acquire() bool {
	n := g.state.Add(1)
	if n&guardClosedBit == 0 {
		return true
	}
	g.decrementAndSignal()
	return false
}

// Release releases a lease acquired by [guard.Acquire].
// It is a run-time error to call Release without a matching Acquire.
func (g *guard) Release() {
	g.decrementAndSignal()
}

func (g *guard) decrementAndSignal() {
	n := g.state.Add(-1)
	if n < 0 || n == guardCountMask {
		panic("unbalanced Release call")
	}
	if n == guardClosedBit {
		g.closeOnce.Do(func() { close(g.done) })
	}
}

// Close prevents future Acquire calls from succeeding.
func (g *guard) Close() {
	g.state.Or(guardClosedBit)
}

// IsClosed reports whether Close has been called.
func (g *guard) IsClosed() bool {
	return g.state.Load()&guardClosedBit != 0
}

// Wait blocks until all in-flight operations have called Release.
// It is a run-time error to call Wait before Close.
func (g *guard) Wait() {
	state := g.state.Load()
	if state&guardClosedBit == 0 {
		panic("Wait called before Close")
	}
	if state == guardClosedBit {
		return
	}
	<-g.done
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.13 && !go1.19

package syncs

import (
	"sync"
	"testing"
	"time"
)

func wantPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		recover()
	}()
	fn()
	t.Fatal("failed to panic")
}

func TestAssertLocked(t *testing.T) {
	m := new(sync.Mutex)
	wantPanic(t, func() { AssertLocked(m) })
	m.Lock()
	AssertLocked(m)
	m.Unlock()
	wantPanic(t, func() { AssertLocked(m) })
	// Test correct handling of mutex with waiter.
	m.Lock()
	AssertLocked(m)
	go func() {
		m.Lock()
		m.Unlock()
	}()
	// Give the goroutine above a few moments to get started.
	// The test will pass whether or not we win the race,
	// but we want to run sometimes, to get the test coverage.
	time.Sleep(10 * time.Millisecond)
	AssertLocked(m)
}

func TestAssertWLocked(t *testing.T) {
	m := new(sync.RWMutex)
	wantPanic(t, func() { AssertWLocked(m) })
	m.Lock()
	AssertWLocked(m)
	m.Unlock()
	wantPanic(t, func() { AssertWLocked(m) })
	// Test correct handling of mutex with waiter.
	m.Lock()
	AssertWLocked(m)
	go func() {
		m.Lock()
		m.Unlock()
	}()
	// Give the goroutine above a few moments to get started.
	// The test will pass whether or not we win the race,
	// but we want to run sometimes, to get the test coverage.
	time.Sleep(10 * time.Millisecond)
	AssertWLocked(m)
}

func TestAssertRLocked(t *testing.T) {
	m := new(sync.RWMutex)
	wantPanic(t, func() { AssertRLocked(m) })

	m.Lock()
	AssertRLocked(m)
	m.Unlock()

	m.RLock()
	AssertRLocked(m)
	m.RUnlock()

	wantPanic(t, func() { AssertRLocked(m) })

	// Test correct handling of mutex with waiter.
	m.RLock()
	AssertRLocked(m)
	go func() {
		m.RLock()
		m.RUnlock()
	}()
	// Give the goroutine above a few moments to get started.
	// The test will pass whether or not we win the race,
	// but we want to run sometimes, to get the test coverage.
	time.Sleep(10 * time.Millisecond)
	AssertRLocked(m)
	m.RUnlock()

	// Test correct handling of rlock with write waiter.
	m.RLock()
	AssertRLocked(m)
	go func() {
		m.Lock()
		m.Unlock()
	}()
	// Give the goroutine above a few moments to get started.
	// The test will pass whether or not we win the race,
	// but we want to run sometimes, to get the test coverage.
	time.Sleep(10 * time.Millisecond)
	AssertRLocked(m)
	m.RUnlock()

	// Test correct handling of rlock with other rlocks.
	// This is a bit racy, but losing the race hurts nothing,
	// and winning the race means correct test coverage.
	m.RLock()
	AssertRLocked(m)
	go func() {
		m.RLock()
		time.Sleep(10 * time.Millisecond)
		m.RUnlock()
	}()
	time.Sleep(5 * time.Millisecond)
	AssertRLocked(m)
	m.RUnlock()
}

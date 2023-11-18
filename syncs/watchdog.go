// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syncs

import (
	"context"
	"sync"
	"time"
)

// Watch monitors mu for contention.
// On first call, and at every tick, Watch locks and unlocks mu.
// (Tick should be large to avoid adding contention to mu.)
// Max is the maximum length of time Watch will wait to acquire the lock.
// The time required to lock mu is sent on the returned channel.
// Watch exits when ctx is done, and closes the returned channel.
func Watch(ctx context.Context, mu sync.Locker, tick, max time.Duration) chan time.Duration {
	// Set up the return channel.
	c := make(chan time.Duration)
	var (
		closemu sync.Mutex
		closed  bool
	)
	sendc := func(d time.Duration) {
		closemu.Lock()
		defer closemu.Unlock()
		if closed {
			// Drop values written after c is closed.
			return
		}
		select {
		case c <- d:
		case <-ctx.Done():
		}
	}
	closec := func() {
		closemu.Lock()
		defer closemu.Unlock()
		close(c)
		closed = true
	}

	// check locks the mutex and writes how long it took to c.
	// check returns ~immediately.
	check := func() {
		// Start a race between two goroutines.
		// One locks the mutex; the other times out.
		// Ensure that only one of the two gets to write its result.
		// Since the common case is that locking the mutex is fast,
		// let the timeout goroutine exit early when that happens.
		var sendonce sync.Once
		done := make(chan bool)
		go func() {
			start := time.Now()
			mu.Lock()
			mu.Unlock()
			elapsed := time.Since(start)
			if elapsed > max {
				elapsed = max
			}
			close(done)
			sendonce.Do(func() { sendc(elapsed) })
		}()
		go func() {
			select {
			case <-time.After(max):
				// the other goroutine may not have sent a value
				sendonce.Do(func() { sendc(max) })
			case <-done:
				// the other goroutine sent a value
			}
		}()
	}

	// Check once at startup.
	// This is mainly to make testing easier.
	check()

	// Start the watchdog goroutine.
	// It checks the mutex every tick, until ctx is done.
	go func() {
		ticker := time.NewTicker(tick)
		for {
			select {
			case <-ctx.Done():
				closec()
				ticker.Stop()
				return
			case <-ticker.C:
				check()
			}
		}
	}()

	return c
}

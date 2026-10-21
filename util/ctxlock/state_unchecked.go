// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ctxlock

import (
	"context"
	"time"
)

// unchecked is an implementation of [State] that trades additional runtime checks
// for performance.
//
// Its zero value carries no mutex lock state and an empty [context.Context].
type unchecked struct {
	context.Context             // nil means an empty context
	mu              mutexHandle // non-nil if owned by this state
}

type (
	alreadyLocked          struct{}
	uncheckedMutex[R Rank] = mutex[R, unchecked]
)

func fromContextUnchecked(ctx context.Context) unchecked {
	return unchecked{ctx, nil}
}

func lockUnchecked[R Rank](parent unchecked, mu *uncheckedMutex[R]) unchecked {
	if !parent.isAlreadyLocked(mu) {
		mu.lock()
		// Locking a mutex creates a new state that must be accessible from any derived state.
		// Normally, this state would be heap-allocated, but we want to avoid allocating new memory
		// on every lock. Instead, we use a storage region within the mutex itself.
		mu.lockState = unchecked{parent.Context, mu}
		return unchecked{&mu.lockState, mu}

	}
	// The mutex is already locked by a parent or ancestor state.
	return unchecked{parent.Context, nil}
}

func (c unchecked) isAlreadyLocked(m mutexHandle) bool {
	switch val := c.Value(m).(type) {
	case nil:
		// No ancestor state associated with this mutex,
		// and locking it does not violate the lock ordering.
		return false
	case error:
		// There's a lock ordering or reentrancy violation.
		panic(val)
	case alreadyLocked:
		// The mutex is reentrant and is already held by a parent
		// or ancestor state.
		return true
	default:
		panic("unreachable")
	}
}

func (c unchecked) unlock() {
	if c.mu != nil {
		c.mu.unlock()
	}
}

// Deadline implements [context.Context].
func (c unchecked) Deadline() (deadline time.Time, ok bool) {
	if c.Context == nil {
		return time.Time{}, false
	}
	return c.Context.Deadline()
}

// Done implements [context.Context].
func (c unchecked) Done() <-chan struct{} {
	if c.Context == nil {
		return nil
	}
	return c.Context.Done()
}

// Err implements [context.Context].
func (c unchecked) Err() error {
	if c.Context == nil {
		return nil
	}
	return c.Context.Err()
}

// Err implements [context.Context].
func (c unchecked) Value(key any) any {
	if mu, ok := key.(mutexHandle); ok {
		if res, done := checkLockOrder(mu, c.mu, alreadyLocked{}); done {
			// We have a definite answer.
			return res
		}
	}
	if c.Context == nil {
		return nil
	}
	return c.Context.Value(key)
}

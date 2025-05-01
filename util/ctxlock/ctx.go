// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ctxlock provides a [context.Context] implementation that carries mutex lock state
// and enables reentrant locking. It offers two implementations: checked and unchecked.
// The checked implementation performs runtime validation to ensure that:
// - a parent context is not unlocked before its child,
// - a context is only unlocked once, and
// - a context is not used after being unlocked.
// The unchecked implementation skips these checks for improved performance.
// It defaults to the checked implementation unless the ts_omit_ctxlock_checks build tag is set.
package ctxlock

import (
	"context"
	"sync"
)

var (
	noneCtx = context.Background()
)

type lockerKey[T any] struct{ key T }

func lockerKeyOf[T sync.Locker](mu T) lockerKey[T] {
	return lockerKey[T]{key: mu}
}

// checked is an implementation of [Context] that performs runtime checks
// to ensure that the context is used correctly.
type checked[T sync.Locker] struct {
	context.Context             // nil after [checked.Unlock] is called
	mu              T           // nil if the context does not track a mutex lock state
	parent          *checked[T] // nil if the context owns the lock
}

func noneChecked[T sync.Locker]() *checked[T] {
	var zero T
	return &checked[T]{noneCtx, zero, nil}
}

func wrapChecked[T sync.Locker](parent context.Context) *checked[T] {
	var zero T
	return &checked[T]{parent, zero, nil}
}

func lockChecked[T, P sync.Locker](parent *checked[P], mu T) *checked[T] {
	checkLockArgs(parent, mu)
	if parentLockCtx, ok := parent.Value(lockerKeyOf(mu)).(*checked[T]); ok {
		if appearsUnlocked(mu) {
			// The parent still owns the lock, but the mutex is unlocked.
			panic("mu is already unlocked")
		}
		return &checked[T]{parent, mu, parentLockCtx}
	}
	mu.Lock()
	return &checked[T]{parent, mu, nil}
}

func (c *checked[T]) Value(key any) any {
	if c.Context == nil {
		panic("use of context after unlock")
	}
	if key == any(lockerKeyOf(c.mu)) {
		return c
	}
	return c.Context.Value(key)
}

func (c *checked[T]) Unlock() {
	var zero T
	switch {
	case c.Context == nil:
		panic("already unlocked")
	case any(c.mu) == any(zero):
		// No-op; the context does not track a mutex lock state,
		// such as when it was created with [noneChecked] or [wrapChecked].
	case appearsUnlocked(c.mu):
		panic("mutex is not locked")
	case c.parent == nil:
		c.mu.Unlock()
	case c.parent.Context == nil:
		panic("parent already unlocked")
	default:
		// No-op; a parent or ancestor will handle unlocking.
	}
	c.Context = nil
}

func checkLockArgs[T interface {
	context.Context
	comparable
}, L sync.Locker](parent T, mu L) {
	var zero T
	var nilLocker L
	if parent == zero {
		panic("nil parent context")
	}
	if any(mu) == any(nilLocker) {
		panic("nil locker")
	}
}

// unchecked is an implementation of [Context] that trades runtime checks for performance.
type unchecked[T sync.Locker] struct {
	context.Context   // always non-nil
	mu              T // non-nil if locked by this context
}

func noneUnchecked[T sync.Locker]() unchecked[T] {
	var zero T
	return unchecked[T]{noneCtx, zero}
}

func wrapUnchecked[T sync.Locker](parent context.Context) unchecked[T] {
	var zero T
	return unchecked[T]{parent, zero}
}

func lockUnchecked[T, P sync.Locker](parent unchecked[P], mu T) unchecked[T] {
	checkLockArgs(parent.Context, mu) // this is cheap, so we do it even in the unchecked case
	if parent.Value(lockerKeyOf(mu)) == nil {
		mu.Lock()
	} else {
		var zero T
		mu = zero // already locked by a parent/ancestor
	}
	return unchecked[T]{parent.Context, mu}
}

func (c unchecked[T]) Value(key any) any {
	if any(key) == any(lockerKeyOf(c.mu)) {
		return key
	}
	return c.Context.Value(key)
}

func (c unchecked[T]) Unlock() {
	var zero T
	if any(c.mu) != any(zero) {
		c.mu.Unlock()
	}
}

type tryLocker interface {
	TryLock() bool
	Unlock()
}

// appearsUnlocked reports whether m is unlocked.
// It may return a false negative if m does not have a TryLock method.
func appearsUnlocked[T sync.Locker](m T) bool {
	if m, ok := any(m).(tryLocker); ok && m.TryLock() {
		m.Unlock()
		return true
	}
	return false
}

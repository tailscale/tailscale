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
	"fmt"
	"reflect"
	"sync"
	"time"
)

type ctxKey struct{ *sync.Mutex }

func ctxKeyOf(mu *sync.Mutex) ctxKey {
	return ctxKey{mu}
}

// checked is an implementation of [Context] that performs runtime checks
// to ensure that the context is used correctly.
//
// Its zero value and a nil pointer carry no lock state and an empty [context.Context].
type checked struct {
	context.Context             // nil if the context does not carry a [context.Context]
	mu              *sync.Mutex // nil if the context does not carry a mutex lock state
	parent          *checked    // nil if the context owns the lock
	unlocked        bool        // whether [checked.Unlock] was called
}

func wrapChecked(parent context.Context) *checked {
	return &checked{parent, nil, nil, false}
}

func lockChecked(parent *checked, mu *sync.Mutex) *checked {
	panicIfNil(mu)
	if parentLockCtx, ok := parent.Value(ctxKeyOf(mu)).(*checked); ok {
		if appearsUnlocked(mu) {
			// The parent still owns the lock, but the mutex is unlocked.
			panic("mu is spuriously unlocked")
		}
		return &checked{parent, mu, parentLockCtx, false}
	}
	mu.Lock()
	return &checked{parent, mu, nil, false}
}

func (c *checked) Deadline() (deadline time.Time, ok bool) {
	c.panicIfUnlocked()
	if c == nil || c.Context == nil {
		return time.Time{}, false
	}
	return c.Context.Deadline()
}

func (c *checked) Done() <-chan struct{} {
	c.panicIfUnlocked()
	if c == nil || c.Context == nil {
		return nil
	}
	return c.Context.Done()
}

func (c *checked) Err() error {
	c.panicIfUnlocked()
	if c == nil || c.Context == nil {
		return nil
	}
	return c.Context.Err()
}

func (c *checked) Value(key any) any {
	c.panicIfUnlocked()
	if c == nil {
		return nil
	}
	if key == ctxKeyOf(c.mu) {
		return c
	}
	return c.Context.Value(key)
}

func (c *checked) Unlock() {
	switch {
	case c == nil:
		// No-op; zero context.
		return
	case c.unlocked:
		panic("already unlocked")
	case c.mu == nil:
		// No-op; the context does not track a mutex lock state,
		// such as when it was created with [noneChecked] or [wrapChecked].
	case c.parent == nil:
		// We own the lock; let's unlock it.
		// This triggers a fatal error if the mutex is already unlocked.
		c.mu.Unlock()
	case c.parent.unlocked:
		// The parent context is already unlocked.
		// The mutex may or may not be locked;
		// something else may have already locked it.
		panic("parent already unlocked")
	case appearsUnlocked(c.mu):
		// The mutex itself is unlocked,
		// even though the parent context is still locked.
		// It may be unlocked by an ancestor context
		// or by something else entirely.
		panic("mutex is not locked")
	default:
		// No-op; a parent or ancestor will handle unlocking.
	}
	c.unlocked = true // mark this context as unlocked
}

func (c *checked) panicIfUnlocked() {
	if c != nil && c.unlocked {
		panic("use of context after unlock")
	}
}

func panicIfNil[T comparable](v T) {
	if reflect.ValueOf(v).IsNil() {
		panic(fmt.Sprintf("nil %T", v))
	}
}

// unchecked is an implementation of [Context] that trades runtime checks for performance.
//
// Its zero value carries no mutex lock state and an empty [context.Context].
type unchecked struct {
	context.Context             // nil if the context does not carry a [context.Context]
	mu              *sync.Mutex // non-nil if locked by this context
}

func wrapUnchecked(parent context.Context) unchecked {
	return unchecked{parent, nil}
}

func lockUnchecked(parent unchecked, mu *sync.Mutex) unchecked {
	if parent.Value(ctxKeyOf(mu)) == nil {
		mu.Lock()
	} else {
		mu = nil // already locked by a parent/ancestor
	}
	return unchecked{parent.Context, mu}
}

func (c unchecked) Deadline() (deadline time.Time, ok bool) {
	if c.Context == nil {
		return time.Time{}, false
	}
	return c.Context.Deadline()
}

func (c unchecked) Done() <-chan struct{} {
	if c.Context == nil {
		return nil
	}
	return c.Context.Done()
}

func (c unchecked) Err() error {
	if c.Context == nil {
		return nil
	}
	return c.Context.Err()
}

func (c unchecked) Value(key any) any {
	if key == ctxKeyOf(c.mu) {
		return key
	}
	if c.Context == nil {
		return nil
	}
	return c.Context.Value(key)
}

func (c unchecked) Unlock() {
	if c.mu != nil {
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

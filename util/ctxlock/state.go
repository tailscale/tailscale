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

// This file contains both the [checked] and [unchecked] implementations of [State].

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

// checked is an implementation of [State] that performs runtime checks
// to ensure the correct order of locking and unlocking.
//
// Its zero value and a nil pointer are valid and carry no lock state
// and an empty [context.Context].
type checked struct {
	context.Context // nil means an empty context

	// mu is the mutex tracked by this state,
	// or nil if it wasn't created with [Lock].
	mu *sync.Mutex

	// parent is an ancestor State associated with the same mutex.
	// It may or may not own the lock (the lock could be held by a further ancestor).
	// The parent is nil if this State is the root of the hierarchy,
	// meaning it owns the lock.
	parent *checked

	// unlocked is whether [checked.Unlock] was called on this state.
	unlocked bool
}

func fromContextChecked(ctx context.Context) *checked {
	return &checked{ctx, nil, nil, false}
}

func lockChecked(parent *checked, mu *sync.Mutex) *checked {
	panicIfNil(mu)
	if parentState, ok := parent.Value(ctxKeyOf(mu)).(*checked); ok {
		if appearsUnlocked(mu) {
			// The parent is already unlocked, but the mutex is not.
			panic(fmt.Sprintf("%T is spuriously unlocked", mu))
		}
		return &checked{parent, mu, parentState, false}
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
		// No-op; zero state.
		return nil
	}
	if key, ok := key.(ctxKey); ok && key.Mutex == c.mu {
		// This is the mutex tracked by this state.
		return c
	}
	if c.Context != nil {
		// Forward the call to the parent context,
		// which may or may not be a [checked] state.
		return c.Context.Value(key)
	}
	return nil
}

func (c *checked) Unlock() {
	switch {
	case c == nil:
		// No-op; zero state.
		return
	case c.unlocked:
		panic("already unlocked")
	case c.mu == nil:
		// No-op; the state does not track a mutex lock state,
		// meaning it was not created with [Lock].
	case c.parent == nil:
		// The state own the mutex's lock; we must unlock it.
		// This triggers a fatal error if the mutex is already unlocked.
		c.mu.Unlock()
	case c.parent.unlocked:
		// The parent state is already unlocked.
		// The mutex may or may not be locked;
		// something else may have already locked it.
		panic("parent already unlocked")
	case appearsUnlocked(c.mu):
		// The mutex itself is unlocked,
		// even though the parent state is still locked.
		// It may be unlocked by an ancestor state
		// or by something else entirely.
		panic("mutex is not locked")
	default:
		// No-op; a parent or ancestor will handle unlocking.
	}
	c.unlocked = true // mark this state as unlocked
}

func (c *checked) panicIfUnlocked() {
	if c != nil && c.unlocked {
		panic("use after unlock")
	}
}

func panicIfNil[T comparable](v T) {
	if reflect.ValueOf(v).IsNil() {
		panic(fmt.Sprintf("nil %T", v))
	}
}

// unchecked is an implementation of [State] that trades runtime checks for performance.
//
// Its zero value carries no mutex lock state and an empty [context.Context].
type unchecked struct {
	context.Context             // nil means an empty context
	mu              *sync.Mutex // non-nil if owned by this state
}

func fromContextUnchecked(ctx context.Context) unchecked {
	return unchecked{ctx, nil}
}

func lockUnchecked(parent unchecked, mu *sync.Mutex) unchecked {
	if parent.Value(ctxKeyOf(mu)) == nil {
		// There's no ancestor state associated with this mutex,
		// so we can lock it.
		mu.Lock()
	} else {
		// The mutex is already locked by a parent/ancestor state.
		mu = nil
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
	if key, ok := key.(ctxKey); ok && key.Mutex == c.mu {
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

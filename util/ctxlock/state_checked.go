// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ctxlock

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
)

// checked is an implementation of [State] with additional runtime checks.
//
// Its zero value and a nil pointer are valid and carry no lock state
// and an empty [context.Context].
type checked struct {
	context.Context // nil means an empty context

	// mu is the mutex locked (or re-locked) by this state,
	// or nil if it wasn't created with [Lock].
	mu mutexHandle

	// parent is the next state in the hierarchy associated with the same mutex.
	// It may or may not own the lock (the lock could be held by a further ancestor).
	//
	// The parent is nil if this state owns the lock, or if it's a zero state.
	parent *checked

	// unlocked is whether [checked.Unlock] was called on this state.
	unlocked bool

	// lockedBy are the program counters of function invocations
	// that locked the mutex, or nil if mu is not owned by this state.
	lockedBy *lockCallers
}

type (
	lockCallers          [5]uintptr
	checkedMutex[R Rank] = mutex[R, lockCallers]
)

func fromContextChecked(ctx context.Context) *checked {
	return &checked{Context: ctx}
}

func lockChecked[R Rank](parent *checked, mu *checkedMutex[R]) *checked {
	if mu == nil {
		panic("nil mutex")
	}
	if parentState, ok := parent.isAlreadyLocked(mu); ok {
		return &checked{parent, mu, parentState, false, nil}
	}
	mu.lock()
	runtime.Callers(4, mu.lockState[:])
	return &checked{parent, mu, nil, false, nil}
}

func (c *checked) isAlreadyLocked(m mutexHandle) (parent *checked, ok bool) {
	switch val := c.Value(m).(type) {
	case nil:
		// No ancestor state associated with this mutex,
		// and locking it does not violate the lock ordering.
		return nil, false
	case error:
		// There's a lock ordering or reentrancy violation.
		panic(val)
	case *checked:
		// The mutex is reentrant and is already held by a parent
		// or ancestor state.
		return val, true
	default:
		panic("unreachable")
	}
}

func (c *checked) unlock() {
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
		c.mu.unlock()
	case c.parent.unlocked:
		// The parent state is already unlocked.
		// The mutex may or may not be locked;
		// something else may have already locked it.
		panic("parent already unlocked")
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

// Deadline implements [context.Context].
func (c *checked) Deadline() (deadline time.Time, ok bool) {
	c.panicIfUnlocked()
	if c == nil || c.Context == nil {
		return time.Time{}, false
	}
	return c.Context.Deadline()
}

// Done implements [context.Context].
func (c *checked) Done() <-chan struct{} {
	c.panicIfUnlocked()
	if c == nil || c.Context == nil {
		return nil
	}
	return c.Context.Done()
}

// Err implements [context.Context].
func (c *checked) Err() error {
	c.panicIfUnlocked()
	if c == nil || c.Context == nil {
		return nil
	}
	return c.Context.Err()
}

// Value implements [context.Context].
func (c *checked) Value(key any) any {
	c.panicIfUnlocked()
	if c == nil {
		// No-op; zero state.
		return nil
	}
	if mu, ok := key.(mutexHandle); ok {
		// Checks whether mu can be acquired after c.mu.
		if res, done := checkLockOrder(mu, c.mu, c); done {
			// We have a definite answer.
			switch res := res.(type) {
			case error:
				// There's a lock ordering or reentrancy violation.
				// Enrich the error with the call stack when the other mutex was locked.
				if lockedBy, ok := c.mu.state().(*lockCallers); ok {
					return LockOrderError{res, *lockedBy}
				}
			default:
				// A reentrant mutex is already locked by a parent or ancestor state.
				return res
			}
		}
	}
	if c.Context != nil {
		// Forward the call to the parent context,
		// which may or may not be a [checked] state.
		return c.Context.Value(key)
	}
	return nil
}

var errAlreadyLocked = errors.New("non-reentrant mutex already locked")

// checkLockOrder determines whether m1 can be acquired after m2.
// It returns an error and true if there's a lock ordering or reentrancy violation,
// or the provided alreadyLocked value and true if m1 and m2 are the same and reentrancy is allowed,
// or nil and false if the caller should continue checking against the next locked mutex.
func checkLockOrder[T any](m1, m2 mutexHandle, alreadyLocked T) (res any, done bool) {
	if m2 == nil {
		// Nothing to check; continue search.
		return nil, false
	}
	r1, r2 := m1.rank(), m2.rank()
	if err := r1.CheckLockAfter(r2); err != nil {
		// There's a lock ordering (or reentrancy) violation.
		return err, true
	}
	if m1 != m2 {
		// There's no lock ordering violation,
		// but the mutex being locked is not the same as the one
		// already locked. We need to continue checking.
		return nil, false
	}
	if _, ok := r1.(NonReentrant); ok {
		// Special handling for the [NonReentrant] rank.
		//
		// For user-defined ranks, reentrancy rules are enforced
		// by the rank implementation itself, since each mutex
		// is expected to have a distinct rank, and the rank
		// can define its own rules. However, the predefined
		// [NonReentrant] rank is shared by multiple mutexes.
		return errAlreadyLocked, true
	}
	// The locking mutex is the same as the one already locked,
	// and the rank allows reentrancy. We found a match.
	return alreadyLocked, true
}

// LockOrderError represents a violation of mutex lock ordering.
//
// This error is not returned directly; it is used in panics to indicate a programming error
// when lock acquisition violates the expected order.
type LockOrderError struct {
	error
	violatedBy lockCallers // the call stack when the other mutex was locked
}

func (e LockOrderError) Error() string {
	return fmt.Sprintf("%s\n\nConflicting lock held at:\n%s", e.error, e.violatedBy)
}

func (c lockCallers) String() string {
	var output string
	frames := runtime.CallersFrames(c[:])
	for {
		frame, more := frames.Next()
		output += fmt.Sprintf("%s\n\t%s:%d\n", frame.Function, frame.File, frame.Line)
		if !more {
			break
		}
	}
	return output
}

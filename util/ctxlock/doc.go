// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ctxlock provides a [Mutex] type and allows to define lock ordering
// and reentrancy rules for mutexes using a [Rank]. It then enforces these
// rules at runtime using a [State] hierarchy.
//
// The package has two implementations: checked and unchecked.
//
// Both implementations support reentrancy and lock ordering,
// but the checked implementation performs additional runtime checks
// and ensures that:
//   - a parent [LockHandle] is not unlocked before its child,
//   - a [LockHandle] is only unlocked once, and
//   - a [State] is not used after being unlocked.
//
// The unchecked implementation skips these checks for improved performance,
// and is enabled in builds with the ts_omit_ctxlock_checks build tag.
//
// Example:
//
//	type Resource struct {
//	  mu Mutex[Reentrant]
//	  value int
//	}
//
//	func (r *Resource) GetValue(ctx State) int {
//	  lock := Lock(ctx, &r.mu)
//	  defer lock.Unlock()
//	  return r.value
//	}
//
//	func (r *Resource) SetValue(ctx State, v int) {
//	  lock := Lock(ctx, &r.mu)
//	  defer lock.Unlock()
//	  r.value = v
//	}
//
//	func (r *Resource) Foo(ctx State, cb func(State) int) int {
//	  lock := Lock(ctx, &r.mu)
//	  defer lock.Unlock()
//	  return cb(lock.State())
//	}
//
//	func main() {
//	  r := Resource{}
//	  r.SetValue(State{}, 42)
//	  v := r.Foo(State{}, func(ctx State) int {
//	    return r.GetValue(ctx)
//	  })
//	  fmt.Println(v) // prints 42
//	}
package ctxlock

import "context"

// IsChecked indicates whether the checked implementation is used.
const IsChecked = useCheckedImpl

// A Mutex is a potentially reentrant mutual exclusion lock
// with a lock hierarchy and reentrancy rules defined by its [Rank].
// The zero value of a Mutex is valid and represents an unlocked mutex.
//
// The lock state of zero or more mutexes held by a given call chain
// is carried by a [State].
//
// A mutex can be locked using [Lock]. The returned [LockHandle] becomes
// the mutex's owner if the mutex wasn't already held by an ancestor [State].
// It can be used to unlock the mutex or access the lock state hierarchy.
//
// It is a runtime error to lock a mutex if its rank's CheckLockAfter
// reports a conflict with any mutex already held along the call chain.
type Mutex[R Rank] struct {
	mutex[R, lockState]
}

// ReentrantMutex is a reentrant [Mutex] with no defined lock hierarchy.
type ReentrantMutex = Mutex[Reentrant]

// State is a [context.Context] that carries the lock state of zero or more mutexes.
//
// Its zero value is valid and represents an unlocked state and an empty context.
type State struct {
	stateImpl
}

// None returns a zero [State].
func None() State {
	return State{}
}

// FromContext returns a [State] that carries the same lock state
// as the given [context.Context].
//
// It's typically used when [context.Context] already handles
// cancellation or deadlines and can be extended to locking as well.
func FromContext(ctx context.Context) State {
	return State{fromContext(ctx)}
}

// Lock locks the specified mutex and becomes its owner, unless it is
// already held by the parent or its ancestor. It returns a [LockHandle]
// that can be used to unlock the mutex or access the modified lock [State].
//
// The parent can be either a [State] or a [context.Context].
// A zero State is a valid parent.
//
// It is a runtime error to pass a nil mutex or to unlock the parent's
// [LockHandle] before the returned one.
func Lock[T context.Context, R Rank](parent T, mu *Mutex[R]) LockHandle {
	//return LockHandle{lock(parent, &mu.mutex)}
	if parent, ok := any(parent).(State); ok {
		return LockHandle{lock(parent.stateImpl, &mu.mutex)}
	}
	return LockHandle{lock(fromContext(parent), &mu.mutex)}
}

// LockHandle allows releasing a mutex acquired with [Lock]
// and provides access to the lock state hierarchy.
type LockHandle struct {
	state stateImpl
}

// State returns the current lock state.
func (h LockHandle) State() State {
	return State{h.state}
}

// Unlock releases the mutex owned by the handle, if any.
// It is a runtime error to call Unlock more than once on the same handle,
// or to unlock a [LockHandle] while its associated [State] is still in use.
func (h LockHandle) Unlock() {
	h.state.unlock()
}

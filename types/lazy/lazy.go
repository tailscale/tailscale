// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package lazy provides types for lazily initialized values.
package lazy

import (
	"sync"
	"sync/atomic"

	"tailscale.com/types/ptr"
)

// nilErrPtr is a sentinel *error value for SyncValue.err to signal
// that SyncValue.v is valid.
var nilErrPtr = ptr.To[error](nil)

// SyncValue is a lazily computed value.
//
// Use either Get or GetErr, depending on whether your fill function returns an
// error.
//
// Recursive use of a SyncValue from its own fill function will deadlock.
//
// SyncValue is safe for concurrent use.
type SyncValue[T any] struct {
	once sync.Once
	v    T

	// err is either:
	//    * nil, if not yet computed
	//    * nilErrPtr, if completed and nil
	//    * non-nil and not nilErrPtr on error.
	//
	// It is an atomic.Pointer so it can be read outside of the sync.Once.Do.
	//
	// Writes to err must happen after a write to v so a caller seeing a non-nil
	// err can safely read v.
	err atomic.Pointer[error]
}

// Set attempts to set z's value to val, and reports whether it succeeded.
// Set only succeeds if none of Get/GetErr/Set have been called before.
func (z *SyncValue[T]) Set(val T) bool {
	var wasSet bool
	z.once.Do(func() {
		z.v = val
		z.err.Store(nilErrPtr) // after write to z.v; see docs
		wasSet = true
	})
	return wasSet
}

// MustSet sets z's value to val, or panics if z already has a value.
func (z *SyncValue[T]) MustSet(val T) {
	if !z.Set(val) {
		panic("Set after already filled")
	}
}

// Get returns z's value, calling fill to compute it if necessary.
// f is called at most once.
func (z *SyncValue[T]) Get(fill func() T) T {
	z.once.Do(func() {
		z.v = fill()
		z.err.Store(nilErrPtr) // after write to z.v; see docs
	})
	return z.v
}

// GetErr returns z's value, calling fill to compute it if necessary.
// f is called at most once, and z remembers both of fill's outputs.
func (z *SyncValue[T]) GetErr(fill func() (T, error)) (T, error) {
	z.once.Do(func() {
		var err error
		z.v, err = fill()

		// Update z.err after z.v; see field docs.
		if err != nil {
			z.err.Store(ptr.To(err))
		} else {
			z.err.Store(nilErrPtr)
		}
	})
	return z.v, *z.err.Load()
}

// Peek returns z's value and a boolean indicating whether the value has been
// set successfully. If a value has not been set, the zero value of T is
// returned.
//
// This function is safe to call concurrently with Get/GetErr/Set, but it's
// undefined whether a value set by a concurrent call will be visible to Peek.
//
// To get any error that's been set, use PeekErr.
//
// If GetErr's fill function returned a valid T and an non-nil error, Peek
// discards that valid T value. PeekErr returns both.
func (z *SyncValue[T]) Peek() (v T, ok bool) {
	if z.err.Load() == nilErrPtr {
		return z.v, true
	}
	var zero T
	return zero, false
}

// PeekErr returns z's value and error and a boolean indicating whether the
// value or error has been set. If ok is false, T and err are the zero value.
//
// This function is safe to call concurrently with Get/GetErr/Set, but it's
// undefined whether a value set by a concurrent call will be visible to Peek.
//
// Unlike Peek, PeekErr reports ok if either v or err has been set, not just v,
// and returns both the T and err returned by GetErr's fill function.
func (z *SyncValue[T]) PeekErr() (v T, err error, ok bool) {
	if e := z.err.Load(); e != nil {
		return z.v, *e, true
	}
	var zero T
	return zero, nil, false
}

// SyncFunc wraps a function to make it lazy.
//
// The returned function calls fill the first time it's called, and returns
// fill's result on every subsequent call.
//
// The returned function is safe for concurrent use.
func SyncFunc[T any](fill func() T) func() T {
	var (
		once sync.Once
		v    T
	)
	return func() T {
		once.Do(func() { v = fill() })
		return v
	}
}

// SyncFuncErr wraps a function to make it lazy.
//
// The returned function calls fill the first time it's called, and returns
// fill's results on every subsequent call.
//
// The returned function is safe for concurrent use.
func SyncFuncErr[T any](fill func() (T, error)) func() (T, error) {
	var (
		once sync.Once
		v    T
		err  error
	)
	return func() (T, error) {
		once.Do(func() { v, err = fill() })
		return v, err
	}
}

// TB is a subset of testing.TB that we use to set up test helpers.
// It's defined here to avoid pulling in the testing package.
type TB interface {
	Helper()
	Cleanup(func())
}

// SetForTest sets z's value and error.
// It's used in tests only and reverts z's state back when tb and all its
// subtests complete.
// It is not safe for concurrent use and must not be called concurrently with
// any SyncValue methods, including another call to itself.
func (z *SyncValue[T]) SetForTest(tb TB, val T, err error) {
	tb.Helper()

	oldErr, oldVal := z.err.Load(), z.v
	z.once.Do(func() {})

	z.v = val
	if err != nil {
		z.err.Store(ptr.To(err))
	} else {
		z.err.Store(nilErrPtr)
	}

	tb.Cleanup(func() {
		if oldErr == nil {
			*z = SyncValue[T]{}
		} else {
			z.v = oldVal
			z.err.Store(oldErr)
		}
	})
}

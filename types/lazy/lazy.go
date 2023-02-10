// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package lazy provides types for lazily initialized values.
package lazy

import "sync"

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
	err  error
}

// Set attempts to set z's value to val, and reports whether it succeeded.
// Set only succeeds if none of Get/GetErr/Set have been called before.
func (z *SyncValue[T]) Set(val T) bool {
	var wasSet bool
	z.once.Do(func() {
		z.v = val
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
	z.once.Do(func() { z.v = fill() })
	return z.v
}

// GetErr returns z's value, calling fill to compute it if necessary.
// f is called at most once, and z remembers both of fill's outputs.
func (z *SyncValue[T]) GetErr(fill func() (T, error)) (T, error) {
	z.once.Do(func() { z.v, z.err = fill() })
	return z.v, z.err
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

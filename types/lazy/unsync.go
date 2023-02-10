// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lazy

// GValue is a lazily computed value.
//
// Use either Get or GetErr, depending on whether your fill function returns an
// error.
//
// Recursive use of a GValue from its own fill function will panic.
//
// GValue is not safe for concurrent use. (Mnemonic: G is for one Goroutine,
// which isn't strictly true if you provide your own synchronization between
// goroutines, but in practice most of our callers have been using it within
// a single goroutine.)
type GValue[T any] struct {
	done    bool
	calling bool
	V       T
	err     error
}

// Set attempts to set z's value to val, and reports whether it succeeded.
// Set only succeeds if none of Get/GetErr/Set have been called before.
func (z *GValue[T]) Set(v T) bool {
	if z.done {
		return false
	}
	if z.calling {
		panic("Set while Get fill is running")
	}
	z.V = v
	z.done = true
	return true
}

// MustSet sets z's value to val, or panics if z already has a value.
func (z *GValue[T]) MustSet(val T) {
	if !z.Set(val) {
		panic("Set after already filled")
	}
}

// Get returns z's value, calling fill to compute it if necessary.
// f is called at most once.
func (z *GValue[T]) Get(fill func() T) T {
	if !z.done {
		if z.calling {
			panic("recursive lazy fill")
		}
		z.calling = true
		z.V = fill()
		z.done = true
		z.calling = false
	}
	return z.V
}

// GetErr returns z's value, calling fill to compute it if necessary.
// f is called at most once, and z remembers both of fill's outputs.
func (z *GValue[T]) GetErr(fill func() (T, error)) (T, error) {
	if !z.done {
		if z.calling {
			panic("recursive lazy fill")
		}
		z.calling = true
		z.V, z.err = fill()
		z.done = true
		z.calling = false
	}
	return z.V, z.err
}

// GFunc wraps a function to make it lazy.
//
// The returned function calls fill the first time it's called, and returns
// fill's result on every subsequent call.
//
// The returned function is not safe for concurrent use.
func GFunc[T any](fill func() T) func() T {
	var v GValue[T]
	return func() T {
		return v.Get(fill)
	}
}

// SyncFuncErr wraps a function to make it lazy.
//
// The returned function calls fill the first time it's called, and returns
// fill's results on every subsequent call.
//
// The returned function is not safe for concurrent use.
func GFuncErr[T any](fill func() (T, error)) func() (T, error) {
	var v GValue[T]
	return func() (T, error) {
		return v.GetErr(fill)
	}
}

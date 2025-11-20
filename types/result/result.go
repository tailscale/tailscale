// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package result contains the Of result type, which is
// either a value or an error.
package result

// Of is either a T value or an error.
//
// Think of it like Rust or Swift's result types.
// It's named "Of" because the fully qualified name
// for callers reads result.Of[T].
type Of[T any] struct {
	v   T // valid if Err is nil; invalid if Err is non-nil
	err error
}

// Value returns a new result with value v,
// without an error.
func Value[T any](v T) Of[T] {
	return Of[T]{v: v}
}

// Error returns a new result with error err.
// If err is nil, the returned result is equivalent
// to calling Value with T's zero value.
func Error[T any](err error) Of[T] {
	return Of[T]{err: err}
}

// MustValue returns r's result value.
// It panics if r.Err returns non-nil.
func (r Of[T]) MustValue() T {
	if r.err != nil {
		panic(r.err)
	}
	return r.v
}

// Value returns r's result value and error.
func (r Of[T]) Value() (T, error) {
	return r.v, r.err
}

// Err returns r's error, if any.
// When r.Err returns nil, it's safe to call r.MustValue without it panicking.
func (r Of[T]) Err() error {
	return r.err
}

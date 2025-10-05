// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package checkchange defines a utility for determining whether a value
// has changed since the last time it was checked.
package checkchange

// EqualCloner is an interface for types that can be compared for equality
// and can be cloned.
type EqualCloner[T any] interface {
	Equal(T) bool
	Clone() T
}

// Update sets *old to a clone of new if they are not equal, returning whether
// they were different.
//
// It only modifies *old if they are different. old must be non-nil.
func Update[T EqualCloner[T]](old *T, new T) (changed bool) {
	if new.Equal(*old) {
		return false
	}
	*old = new.Clone()
	return true
}

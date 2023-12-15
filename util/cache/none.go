// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cache

// None provides no caching and always calls the provided FillFunc.
//
// It is safe for concurrent use if the underlying FillFunc is.
type None[K comparable, V any] struct{}

// Get always calls the provided FillFunc and returns what it does.
func (c None[K, V]) Get(_ K, f FillFunc[V]) (V, error) {
	v, _, e := f()
	return v, e
}

// Forget implements Cache.
func (c None[K, V]) Forget() {}

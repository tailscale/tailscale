// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lazy

import "tailscale.com/util/mak"

// GMap is a map of lazily computed [GValue] pointers, keyed by a comparable
// type.
//
// Use either Get or GetErr, depending on whether your fill function returns an
// error.
//
// GMap is not safe for concurrent use.
type GMap[K comparable, V any] struct {
	store map[K]*GValue[V]
}

// Len returns the number of entries in the map.
func (s *GMap[K, V]) Len() int {
	return len(s.store)
}

// Set attempts to set the value of k to v, and reports whether it succeeded.
// Set only succeeds if k has never been called with Get/GetErr/Set before.
func (s *GMap[K, V]) Set(k K, v V) bool {
	z, ok := s.store[k]
	if !ok {
		z = new(GValue[V])
		mak.Set(&s.store, k, z)
	}
	return z.Set(v)
}

// MustSet sets the value of k to v, or panics if k already has a value.
func (s *GMap[K, V]) MustSet(k K, v V) {
	if !s.Set(k, v) {
		panic("Set after already filled")
	}
}

// Get returns the value for k, computing it with fill if it's not already
// present.
func (s *GMap[K, V]) Get(k K, fill func() V) V {
	z, ok := s.store[k]
	if !ok {
		z = new(GValue[V])
		mak.Set(&s.store, k, z)
	}
	return z.Get(fill)
}

// GetErr returns the value for k, computing it with fill if it's not already
// present.
func (s *GMap[K, V]) GetErr(k K, fill func() (V, error)) (V, error) {
	z, ok := s.store[k]
	if !ok {
		z = new(GValue[V])
		mak.Set(&s.store, k, z)
	}
	return z.GetErr(fill)
}

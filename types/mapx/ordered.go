// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mapx contains extra map types and functions.
package mapx

import (
	"iter"
	"slices"
)

// OrderedMap is a map that maintains the order of its keys.
//
// It is meant for maps that only grow or that are small;
// is it not optimized for deleting keys.
//
// The zero value is ready to use.
//
// Locking-wise, it has the same rules as a regular Go map:
// concurrent reads are safe, but not writes.
type OrderedMap[K comparable, V any] struct {
	// m is the underlying map.
	m map[K]V

	// keys is the order of keys in the map.
	keys []K
}

func (m *OrderedMap[K, V]) init() {
	if m.m == nil {
		m.m = make(map[K]V)
	}
}

// Set sets the value for the given key in the map.
//
// If the key already exists, it updates the value and keeps the order.
func (m *OrderedMap[K, V]) Set(key K, value V) {
	m.init()
	len0 := len(m.keys)
	m.m[key] = value
	if len(m.m) > len0 {
		// New key (not an update)
		m.keys = append(m.keys, key)
	}
}

// Get returns the value for the given key in the map.
// If the key does not exist, it returns the zero value for V.
func (m *OrderedMap[K, V]) Get(key K) V {
	return m.m[key]
}

// GetOk returns the value for the given key in the map
// and whether it was present in the map.
func (m *OrderedMap[K, V]) GetOk(key K) (_ V, ok bool) {
	v, ok := m.m[key]
	return v, ok
}

// Contains reports whether the map contains the given key.
func (m *OrderedMap[K, V]) Contains(key K) bool {
	_, ok := m.m[key]
	return ok
}

// Delete removes the key from the map.
//
// The cost is O(n) in the number of keys in the map.
func (m *OrderedMap[K, V]) Delete(key K) {
	len0 := len(m.m)
	delete(m.m, key)
	if len(m.m) == len0 {
		// Wasn't present; no need to adjust keys.
		return
	}
	was := m.keys
	m.keys = m.keys[:0]
	for _, k := range was {
		if k != key {
			m.keys = append(m.keys, k)
		}
	}
}

// All yields all the keys and values, in the order they were inserted.
func (m *OrderedMap[K, V]) All() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for _, k := range m.keys {
			if !yield(k, m.m[k]) {
				return
			}
		}
	}
}

// Keys yields the map keys, in the order they were inserted.
func (m *OrderedMap[K, V]) Keys() iter.Seq[K] {
	return slices.Values(m.keys)
}

// Values yields the map values, in the order they were inserted.
func (m *OrderedMap[K, V]) Values() iter.Seq[V] {
	return func(yield func(V) bool) {
		for _, k := range m.keys {
			if !yield(m.m[k]) {
				return
			}
		}
	}
}

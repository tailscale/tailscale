// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mak helps make maps. It contains generic helpers to make/assign
// things, notably to maps, but also slices.
package mak

// Set populates an entry in a map, making the map if necessary.
//
// That is, it assigns (*m)[k] = v, making *m if it was nil.
func Set[K comparable, V any, T ~map[K]V](m *T, k K, v V) {
	if *m == nil {
		*m = make(map[K]V)
	}
	(*m)[k] = v
}

// NonNilSliceForJSON makes sure that *slicePtr is non-nil so it will
// won't be omitted from JSON serialization and possibly confuse JavaScript
// clients expecting it to be present.
func NonNilSliceForJSON[T any, S ~[]T](slicePtr *S) {
	if *slicePtr != nil {
		return
	}
	*slicePtr = make([]T, 0)
}

// NonNilMapForJSON makes sure that *slicePtr is non-nil so it will
// won't be omitted from JSON serialization and possibly confuse JavaScript
// clients expecting it to be present.
func NonNilMapForJSON[K comparable, V any, M ~map[K]V](mapPtr *M) {
	if *mapPtr != nil {
		return
	}
	*mapPtr = make(M)
}

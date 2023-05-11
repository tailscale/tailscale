// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package set contains set types.
package set

// Set is a set of T.
type Set[T comparable] map[T]struct{}

// Add adds e to the set.
func (s Set[T]) Add(e T) { s[e] = struct{}{} }

// Contains reports whether s contains e.
func (s Set[T]) Contains(e T) bool {
	_, ok := s[e]
	return ok
}

// Len reports the number of items in s.
func (s Set[T]) Len() int { return len(s) }

// HandleSet is a set of T.
//
// It is not safe for concurrent use.
type HandleSet[T any] map[Handle]T

// Handle is a opaque comparable value that's used as the map key
// in a HandleSet. The only way to get one is to call HandleSet.Add.
type Handle struct {
	v *byte
}

// Add adds the element (map value) e to the set.
//
// It returns the handle (map key) with which e can be removed, using a map
// delete.
func (s *HandleSet[T]) Add(e T) Handle {
	h := Handle{new(byte)}
	if *s == nil {
		*s = make(HandleSet[T])
	}
	(*s)[h] = e
	return h
}

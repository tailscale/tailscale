// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package set

// HandleSet is a set of T.
//
// It is not safe for concurrent use.
type HandleSet[T any] map[Handle]T

// Handle is an opaque comparable value that's used as the map key in a
// HandleSet. The only way to get one is to call HandleSet.Add.
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

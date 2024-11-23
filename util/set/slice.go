// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package set

import (
	"slices"

	"tailscale.com/types/views"
)

// Slice is a set of elements tracked in a slice of unique elements.
type Slice[T comparable] struct {
	slice []T
	set   map[T]bool // nil until/unless slice is large enough
}

// Slice returns a view of the underlying slice.
// The elements are in order of insertion.
// The returned value is only valid until ss is modified again.
func (ss *Slice[T]) Slice() views.Slice[T] { return views.SliceOf(ss.slice) }

// Len returns the number of elements in the set.
func (ss *Slice[T]) Len() int { return len(ss.slice) }

// Contains reports whether v is in the set.
// The amortized cost is O(1).
func (ss *Slice[T]) Contains(v T) bool {
	if ss.set != nil {
		return ss.set[v]
	}
	return slices.Index(ss.slice, v) != -1
}

// Remove removes v from the set.
// The cost is O(n).
func (ss *Slice[T]) Remove(v T) {
	if ss.set != nil {
		if !ss.set[v] {
			return
		}
		delete(ss.set, v)
	}
	if ix := slices.Index(ss.slice, v); ix != -1 {
		ss.slice = append(ss.slice[:ix], ss.slice[ix+1:]...)
	}
}

// Add adds each element in vs to the set.
// The amortized cost is O(1) per element.
func (ss *Slice[T]) Add(vs ...T) {
	for _, v := range vs {
		if ss.Contains(v) {
			continue
		}
		ss.slice = append(ss.slice, v)
		if ss.set != nil {
			ss.set[v] = true
		} else if len(ss.slice) > 8 {
			ss.set = make(map[T]bool, len(ss.slice))
			for _, v := range ss.slice {
				ss.set[v] = true
			}
		}
	}
}

// AddSlice adds all elements in vs to the set.
func (ss *Slice[T]) AddSlice(vs views.Slice[T]) {
	for _, v := range vs.All() {
		ss.Add(v)
	}
}

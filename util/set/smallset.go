// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package set

import (
	"iter"
	"maps"

	"tailscale.com/types/structs"
)

// SmallSet is a set that is optimized for reducing memory overhead when the
// expected size of the set is 0 or 1 elements.
//
// The zero value of SmallSet is a usable empty set.
//
// When storing a SmallSet in a map as a value type, it is important to re-assign
// the map entry after calling Add or Delete, as the SmallSet's representation
// may change.
//
// Copying a SmallSet by value may alias the previous value. Use the Clone method
// to create a new SmallSet with the same contents.
type SmallSet[T comparable] struct {
	_   structs.Incomparable // to prevent == mistakes
	one T                    // if non-zero, then single item in set
	m   Set[T]               // if non-nil, the set of items, which might be size 1 if it's the zero value of T
}

// Values returns an iterator over the elements of the set.
// The iterator will yield the elements in no particular order.
func (s SmallSet[T]) Values() iter.Seq[T] {
	if s.m != nil {
		return maps.Keys(s.m)
	}
	var zero T
	return func(yield func(T) bool) {
		if s.one != zero {
			yield(s.one)
		}
	}
}

// Contains reports whether e is in the set.
func (s SmallSet[T]) Contains(e T) bool {
	if s.m != nil {
		return s.m.Contains(e)
	}
	var zero T
	return e != zero && s.one == e
}

// SoleElement returns the single value in the set, if the set has exactly one
// element.
//
// If the set is empty or has more than one element, ok will be false and e will
// be the zero value of T.
func (s SmallSet[T]) SoleElement() (e T, ok bool) {
	return s.one, s.Len() == 1
}

// Add adds e to the set.
//
// When storing a SmallSet in a map as a value type, it is important to
// re-assign the map entry after calling Add or Delete, as the SmallSet's
// representation may change.
func (s *SmallSet[T]) Add(e T) {
	var zero T
	if s.m != nil {
		s.m.Add(e)
		return
	}
	// Non-zero elements can go into s.one.
	if e != zero {
		if s.one == zero {
			s.one = e // Len 0 to Len 1
			return
		}
		if s.one == e {
			return // dup
		}
	}
	// Need to make a multi map, either
	// because we now have two items, or
	// because e is the zero value.
	s.m = Set[T]{}
	if s.one != zero {
		s.m.Add(s.one) // move single item to multi
	}
	s.m.Add(e) // add new item, possibly zero
	s.one = zero
}

// Len reports the number of elements in the set.
func (s SmallSet[T]) Len() int {
	var zero T
	if s.m != nil {
		return s.m.Len()
	}
	if s.one != zero {
		return 1
	}
	return 0
}

// Delete removes e from the set.
//
// When storing a SmallSet in a map as a value type, it is important to
// re-assign the map entry after calling Add or Delete, as the SmallSet's
// representation may change.
func (s *SmallSet[T]) Delete(e T) {
	var zero T
	if s.m == nil {
		if s.one == e {
			s.one = zero
		}
		return
	}
	s.m.Delete(e)

	// If the map size drops to zero, that means
	// it only contained the zero value of T.
	if s.m.Len() == 0 {
		s.m = nil
		return
	}

	// If the map size drops to one element and doesn't
	// contain the zero value, we can switch back to the
	// single-item representation.
	if s.m.Len() == 1 {
		for v := range s.m {
			if v != zero {
				s.one = v
				s.m = nil
			}
		}
	}
	return
}

// Clone returns a copy of s that doesn't alias the original.
func (s SmallSet[T]) Clone() SmallSet[T] {
	return SmallSet[T]{
		one: s.one,
		m:   maps.Clone(s.m), // preserves nilness
	}
}

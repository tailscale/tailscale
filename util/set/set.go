// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package set contains set types.
package set

import (
	"encoding/json"
	"maps"
)

// Set is a set of T.
type Set[T comparable] map[T]struct{}

// SetOf returns a new set constructed from the elements in slice.
func SetOf[T comparable](slice []T) Set[T] {
	s := make(Set[T])
	s.AddSlice(slice)
	return s
}

// Clone returns a new set cloned from the elements in s.
func (s Set[T]) Clone() Set[T] {
	return maps.Clone(s)
}

// Add adds e to s.
func (s Set[T]) Add(e T) { s[e] = struct{}{} }

// AddSlice adds each element of es to s.
func (s Set[T]) AddSlice(es []T) {
	for _, e := range es {
		s.Add(e)
	}
}

// AddSet adds each element of es to s.
func (s Set[T]) AddSet(es Set[T]) {
	for e := range es {
		s.Add(e)
	}
}

// Slice returns the elements of the set as a slice. The elements will not be
// in any particular order.
func (s Set[T]) Slice() []T {
	es := make([]T, 0, s.Len())
	for k := range s {
		es = append(es, k)
	}
	return es
}

// Delete removes e from the set.
func (s Set[T]) Delete(e T) { delete(s, e) }

// Contains reports whether s contains e.
func (s Set[T]) Contains(e T) bool {
	_, ok := s[e]
	return ok
}

// Len reports the number of items in s.
func (s Set[T]) Len() int { return len(s) }

// Equal reports whether s is equal to other.
func (s Set[T]) Equal(other Set[T]) bool {
	return maps.Equal(s, other)
}

func (s Set[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Slice())
}

func (s *Set[T]) UnmarshalJSON(buf []byte) error {
	var ss []T
	if err := json.Unmarshal(buf, &ss); err != nil {
		return err
	}
	*s = SetOf(ss)
	return nil
}

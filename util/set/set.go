// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package set contains set types.
package set

import (
	"encoding/json"
	"maps"
	"reflect"
	"sort"
)

// Set is a set of T.
type Set[T comparable] map[T]struct{}

// SetOf returns a new set constructed from the elements in slice.
func SetOf[T comparable](slice []T) Set[T] {
	return Of(slice...)
}

// Of returns a new set constructed from the elements in slice.
func Of[T comparable](slice ...T) Set[T] {
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

// Make lazily initializes the map pointed to by s to be non-nil.
func (s *Set[T]) Make() {
	if *s == nil {
		*s = make(Set[T])
	}
}

// Slice returns the elements of the set as a slice. If the element type is
// ordered (integers, floats, or strings), the elements are returned in sorted
// order. Otherwise, the order is not defined.
func (s Set[T]) Slice() []T {
	es := make([]T, 0, s.Len())
	for k := range s {
		es = append(es, k)
	}
	if f := genOrderedSwapper(reflect.TypeFor[T]()); f != nil {
		sort.Slice(es, f(reflect.ValueOf(es)))
	}
	return es
}

// genOrderedSwapper returns a generator for a swap function that can be used to
// sort a slice of the given type. If rt is not an ordered type,
// genOrderedSwapper returns nil.
func genOrderedSwapper(rt reflect.Type) func(reflect.Value) func(i, j int) bool {
	switch rt.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return func(rv reflect.Value) func(i, j int) bool {
			return func(i, j int) bool {
				return rv.Index(i).Uint() < rv.Index(j).Uint()
			}
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return func(rv reflect.Value) func(i, j int) bool {
			return func(i, j int) bool {
				return rv.Index(i).Int() < rv.Index(j).Int()
			}
		}
	case reflect.Float32, reflect.Float64:
		return func(rv reflect.Value) func(i, j int) bool {
			return func(i, j int) bool {
				return rv.Index(i).Float() < rv.Index(j).Float()
			}
		}
	case reflect.String:
		return func(rv reflect.Value) func(i, j int) bool {
			return func(i, j int) bool {
				return rv.Index(i).String() < rv.Index(j).String()
			}
		}
	}
	return nil
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

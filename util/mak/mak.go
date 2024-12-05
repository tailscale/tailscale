// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mak helps make maps. It contains generic helpers to make/assign
// things, notably to maps, but also slices.
package mak

import (
	"fmt"
	"reflect"
)

// Set populates an entry in a map, making the map if necessary.
//
// That is, it assigns (*m)[k] = v, making *m if it was nil.
func Set[K comparable, V any, T ~map[K]V](m *T, k K, v V) {
	if *m == nil {
		*m = make(map[K]V)
	}
	(*m)[k] = v
}

// NonNil takes a pointer to a Go data structure
// (currently only a slice or a map) and makes sure it's non-nil for
// JSON serialization. (In particular, JavaScript clients usually want
// the field to be defined after they decode the JSON.)
//
// Deprecated: use NonNilSliceForJSON or NonNilMapForJSON instead.
func NonNil(ptr any) {
	if ptr == nil {
		panic("nil interface")
	}
	rv := reflect.ValueOf(ptr)
	if rv.Kind() != reflect.Ptr {
		panic(fmt.Sprintf("kind %v, not Ptr", rv.Kind()))
	}
	if rv.Pointer() == 0 {
		panic("nil pointer")
	}
	rv = rv.Elem()
	if rv.Pointer() != 0 {
		return
	}
	switch rv.Type().Kind() {
	case reflect.Slice:
		rv.Set(reflect.MakeSlice(rv.Type(), 0, 0))
	case reflect.Map:
		rv.Set(reflect.MakeMap(rv.Type()))
	}
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

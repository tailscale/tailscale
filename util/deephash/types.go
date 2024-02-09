// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package deephash

import (
	"net/netip"
	"reflect"
	"time"
)

var (
	timeTimeType   = reflect.TypeFor[time.Time]()
	netipAddrType  = reflect.TypeFor[netip.Addr]()
	selfHasherType = reflect.TypeFor[SelfHasher]()
)

// typeIsSpecialized reports whether this type has specialized hashing.
// These are never memory hashable and never considered recursive.
func typeIsSpecialized(t reflect.Type) bool {
	switch t {
	case timeTimeType, netipAddrType:
		return true
	default:
		if t.Kind() != reflect.Pointer && t.Kind() != reflect.Interface {
			if t.Implements(selfHasherType) || reflect.PointerTo(t).Implements(selfHasherType) {
				return true
			}
		}
		return false
	}
}

// typeIsMemHashable reports whether t can be hashed by directly hashing its
// contiguous bytes in memory (e.g. structs with gaps are not mem-hashable).
func typeIsMemHashable(t reflect.Type) bool {
	if typeIsSpecialized(t) {
		return false
	}
	if t.Size() == 0 {
		return true
	}
	switch t.Kind() {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Complex64, reflect.Complex128:
		return true
	case reflect.Array:
		return typeIsMemHashable(t.Elem())
	case reflect.Struct:
		var sumFieldSize uintptr
		for i, numField := 0, t.NumField(); i < numField; i++ {
			sf := t.Field(i)
			if !typeIsMemHashable(sf.Type) {
				return false
			}
			sumFieldSize += sf.Type.Size()
		}
		return sumFieldSize == t.Size() // ensure no gaps
	}
	return false
}

// typeIsRecursive reports whether t has a path back to itself.
// For interfaces, it currently always reports true.
func typeIsRecursive(t reflect.Type) bool {
	inStack := map[reflect.Type]bool{}
	var visitType func(t reflect.Type) (isRecursiveSoFar bool)
	visitType = func(t reflect.Type) (isRecursiveSoFar bool) {
		// Check whether we have seen this type before.
		if inStack[t] {
			return true
		}
		inStack[t] = true
		defer func() {
			delete(inStack, t)
		}()

		// Types with specialized hashing are never considered recursive.
		if typeIsSpecialized(t) {
			return false
		}

		// Any type that is memory hashable must not be recursive since
		// cycles can only occur if pointers are involved.
		if typeIsMemHashable(t) {
			return false
		}

		// Recursively check types that may contain pointers.
		switch t.Kind() {
		default:
			panic("unhandled kind " + t.Kind().String())
		case reflect.String, reflect.UnsafePointer, reflect.Func:
			return false
		case reflect.Interface:
			// Assume the worst for now. TODO(bradfitz): in some cases
			// we should be able to prove that it's not recursive. Not worth
			// it for now.
			return true
		case reflect.Array, reflect.Chan, reflect.Pointer, reflect.Slice:
			return visitType(t.Elem())
		case reflect.Map:
			return visitType(t.Key()) || visitType(t.Elem())
		case reflect.Struct:
			for i, numField := 0, t.NumField(); i < numField; i++ {
				if visitType(t.Field(i).Type) {
					return true
				}
			}
			return false
		}
	}
	return visitType(t)
}

// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package deephash

import "reflect"

// typeIsMemHashable reports whether t can be hashed by directly hashing its
// contiguous bytes in memory (e.g. structs with gaps are not mem-hashable).
func typeIsMemHashable(t reflect.Type) bool {
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
			if t.String() == "intern.Value" {
				// Otherwise its interface{} makes this return true.
				return false
			}
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

// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package uniq provides removal of adjacent duplicate elements in slices.
// It is similar to the unix command uniq.
package uniq

import (
	"fmt"
	"reflect"
)

type badTypeError struct {
	typ reflect.Type
}

func (e badTypeError) Error() string {
	return fmt.Sprintf("uniq.ModifySlice's first argument must have type *[]T, got %v", e.typ)
}

// ModifySlice removes adjacent duplicate elements from the slice pointed to by sliceptr.
// It adjusts the length of the slice appropriately and zeros the tail.
// eq reports whether (*sliceptr)[i] and (*sliceptr)[j] are equal.
// ModifySlice does O(len(*sliceptr)) operations.
func ModifySlice(sliceptr any, eq func(i, j int) bool) {
	rvp := reflect.ValueOf(sliceptr)
	if rvp.Type().Kind() != reflect.Ptr {
		panic(badTypeError{rvp.Type()})
	}
	rv := rvp.Elem()
	if rv.Type().Kind() != reflect.Slice {
		panic(badTypeError{rvp.Type()})
	}

	length := rv.Len()
	dst := 0
	for i := 1; i < length; i++ {
		if eq(dst, i) {
			continue
		}
		dst++
		// slice[dst] = slice[i]
		rv.Index(dst).Set(rv.Index(i))
	}

	end := dst + 1
	var zero reflect.Value
	if end < length {
		zero = reflect.Zero(rv.Type().Elem())
	}

	// for i := range slice[end:] {
	//   size[i] = 0/nil/{}
	// }
	for i := end; i < length; i++ {
		// slice[i] = 0/nil/{}
		rv.Index(i).Set(zero)
	}

	// slice = slice[:end]
	if end < length {
		rv.SetLen(end)
	}
}

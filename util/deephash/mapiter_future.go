// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build tailscale_go
// +build tailscale_go

package deephash

import "reflect"

// iterKey returns the current iter key.
// scratch is a re-usable reflect.Value.
// iterKey may store the iter key in scratch and return scratch,
// or it may allocate and return a new reflect.Value.
func iterKey(iter *reflect.MapIter, scratch reflect.Value) reflect.Value {
	iter.SetKey(scratch)
	return scratch
}

// iterVal returns the current iter val.
// scratch is a re-usable reflect.Value.
// iterVal may store the iter val in scratch and return scratch,
// or it may allocate and return a new reflect.Value.
func iterVal(iter *reflect.MapIter, scratch reflect.Value) reflect.Value {
	iter.SetValue(scratch)
	return scratch
}

// mapIter returns a map iterator for mapVal.
// scratch is a re-usable reflect.MapIter.
// mapIter may re-use scratch and return it,
// or it may allocate and return a new *reflect.MapIter.
// If mapVal is the zero reflect.Value, mapIter may return nil.
func mapIter(scratch *reflect.MapIter, mapVal reflect.Value) *reflect.MapIter {
	scratch.Reset(mapVal) // always Reset, to allow the caller to avoid pinning memory
	if !mapVal.IsValid() {
		// Returning scratch would also be OK.
		// Do this for consistency with the non-optimized version.
		return nil
	}
	return scratch
}

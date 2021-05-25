// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !tailscale_go

package deephash

import "reflect"

// iterKey returns the current iter key.
// scratch is a re-usable reflect.Value.
// iterKey may store the iter key in scratch and return scratch,
// or it may allocate and return a new reflect.Value.
func iterKey(iter *reflect.MapIter, _ reflect.Value) reflect.Value {
	return iter.Key()
}

// iterVal returns the current iter val.
// scratch is a re-usable reflect.Value.
// iterVal may store the iter val in scratch and return scratch,
// or it may allocate and return a new reflect.Value.
func iterVal(iter *reflect.MapIter, _ reflect.Value) reflect.Value {
	return iter.Value()
}

// mapIter returns a map iterator for mapVal.
// scratch is a re-usable reflect.MapIter.
// mapIter may re-use scratch and return it,
// or it may allocate and return a new *reflect.MapIter.
// If mapVal is the zero reflect.Value, mapIter may return nil.
func mapIter(_ *reflect.MapIter, mapVal reflect.Value) *reflect.MapIter {
	if !mapVal.IsValid() {
		return nil
	}
	return mapVal.MapRange()
}

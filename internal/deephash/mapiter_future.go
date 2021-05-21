// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !tailscale_go

package deephash

import "reflect"

func iterKey(iter *reflect.MapIter, scratch reflect.Value) reflect.Value {
	return iter.Key()
}

func iterVal(iter *reflect.MapIter, scratch reflect.Value) reflect.Value {
	return iter.Value()
}

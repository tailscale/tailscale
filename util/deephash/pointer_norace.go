// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !race

package deephash

import "reflect"

type pointer = unsafePointer

// pointerOf returns a pointer from v, which must be a reflect.Pointer.
func pointerOf(v reflect.Value) pointer { return unsafePointerOf(v) }

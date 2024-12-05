// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !race

package deephash

import "reflect"

type pointer = unsafePointer

// pointerOf returns a pointer from v, which must be a reflect.Pointer.
func pointerOf(v reflect.Value) pointer { return unsafePointerOf(v) }

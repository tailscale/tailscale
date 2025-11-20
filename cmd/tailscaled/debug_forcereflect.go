// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_debug_forcereflect

// This file exists for benchmarking binary sizes. When the build tag is
// enabled, it forces use of part of the reflect package that makes the Go
// linker go into conservative retention mode where its deadcode pass can't
// eliminate exported method.

package main

import (
	"reflect"
	"time"
)

func init() {
	// See Go's src/cmd/compile/internal/walk/expr.go:usemethod for
	// why this is isn't a const.
	name := []byte("Bar")
	if time.Now().Unix()&1 == 0 {
		name[0] = 'X'
	}
	_, _ = reflect.TypeOf(12).MethodByName(string(name))
}

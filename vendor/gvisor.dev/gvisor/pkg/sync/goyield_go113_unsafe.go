// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.13 && !go1.14
// +build go1.13,!go1.14

package sync

import (
	"runtime"
)

func goyield() {
	// goyield is not available until Go 1.14.
	runtime.Gosched()
}

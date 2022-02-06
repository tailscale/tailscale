// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !checklocks
// +build !checklocks

package sync

import (
	"unsafe"
)

func noteLock(l unsafe.Pointer) {
}

func noteUnlock(l unsafe.Pointer) {
}

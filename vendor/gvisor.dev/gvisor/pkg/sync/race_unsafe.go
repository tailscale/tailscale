// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build race
// +build race

package sync

import (
	"runtime"
	"unsafe"
)

// RaceEnabled is true if the Go data race detector is enabled.
const RaceEnabled = true

// RaceDisable has the same semantics as runtime.RaceDisable.
func RaceDisable() {
	runtime.RaceDisable()
}

// RaceEnable has the same semantics as runtime.RaceEnable.
func RaceEnable() {
	runtime.RaceEnable()
}

// RaceAcquire has the same semantics as runtime.RaceAcquire.
func RaceAcquire(addr unsafe.Pointer) {
	runtime.RaceAcquire(addr)
}

// RaceRelease has the same semantics as runtime.RaceRelease.
func RaceRelease(addr unsafe.Pointer) {
	runtime.RaceRelease(addr)
}

// RaceReleaseMerge has the same semantics as runtime.RaceReleaseMerge.
func RaceReleaseMerge(addr unsafe.Pointer) {
	runtime.RaceReleaseMerge(addr)
}

// RaceUncheckedAtomicCompareAndSwapUintptr is equivalent to
// sync/atomic.CompareAndSwapUintptr, but is not checked by the race detector.
// This is necessary when implementing gopark callbacks, since no race context
// is available during their execution.
func RaceUncheckedAtomicCompareAndSwapUintptr(ptr *uintptr, old, new uintptr) bool

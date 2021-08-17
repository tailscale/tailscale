// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.13 && !go1.18
// +build go1.13,!go1.18

// This file makes assumptions about the inner workings of sync.Mutex and sync.RWMutex.
// This includes not just their memory layout but their invariants and functionality.
// To prevent accidents, it is limited to a known good subset of Go versions.

package syncs

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

const (
	mutexLocked = 1

	// sync.Mutex field offsets
	stateOffset = 0

	// sync.RWMutext field offsets
	mutexOffset       = 0
	readerCountOffset = 16
)

// add returns a pointer with value p + off.
func add(p unsafe.Pointer, off uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(p) + off)
}

// AssertLocked panics if m is not locked.
func AssertLocked(m *sync.Mutex) {
	p := add(unsafe.Pointer(m), stateOffset)
	if atomic.LoadInt32((*int32)(p))&mutexLocked == 0 {
		panic("mutex is not locked")
	}
}

// AssertRLocked panics if rw is not locked for reading or writing.
func AssertRLocked(rw *sync.RWMutex) {
	p := add(unsafe.Pointer(rw), readerCountOffset)
	if atomic.LoadInt32((*int32)(p)) != 0 {
		// There are readers present or writers pending, so someone has a read lock.
		return
	}
	// No readers.
	AssertWLocked(rw)
}

// AssertWLocked panics if rw is not locked for writing.
func AssertWLocked(rw *sync.RWMutex) {
	m := (*sync.Mutex)(add(unsafe.Pointer(rw), mutexOffset))
	AssertLocked(m)
}

// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build go1.12 && !go1.19
// +build go1.12,!go1.19

// Check type signatures when updating Go version.

// Package goid provides the Get function.
package goid

// Get returns the ID of the current goroutine.
func Get() int64 {
	return getg().goid
}

// Structs from Go runtime. These may change in the future and require
// updating. These structs are currently the same on both AMD64 and ARM64,
// but may diverge in the future.

type stack struct {
	lo uintptr
	hi uintptr
}

type gobuf struct {
	sp   uintptr
	pc   uintptr
	g    uintptr
	ctxt uintptr
	ret  uint64
	lr   uintptr
	bp   uintptr
}

type g struct {
	stack       stack
	stackguard0 uintptr
	stackguard1 uintptr

	_panic       uintptr
	_defer       uintptr
	m            uintptr
	sched        gobuf
	syscallsp    uintptr
	syscallpc    uintptr
	stktopsp     uintptr
	param        uintptr
	atomicstatus uint32
	stackLock    uint32
	goid         int64

	// More fields...
	//
	// We only use goid and the fields before it are only listed to
	// calculate the correct offset.
}

// Defined in assembly. This can't use go:linkname since runtime.getg() isn't a
// real function, it's a compiler intrinsic.
func getg() *g

// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build checklocks
// +build checklocks

package sync

import (
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"gvisor.dev/gvisor/pkg/goid"
)

// gLocks contains metadata about the locks held by a goroutine.
type gLocks struct {
	locksHeld []unsafe.Pointer
}

// map[goid int]*gLocks
//
// Each key may only be written by the G with the goid it refers to.
//
// Note that entries are not evicted when a G exit, causing unbounded growth
// with new G creation / destruction. If this proves problematic, entries could
// be evicted when no locks are held at the expense of more allocations when
// taking top-level locks.
var locksHeld sync.Map

func getGLocks() *gLocks {
	id := goid.Get()

	var locks *gLocks
	if l, ok := locksHeld.Load(id); ok {
		locks = l.(*gLocks)
	} else {
		locks = &gLocks{
			// Initialize space for a few locks.
			locksHeld: make([]unsafe.Pointer, 0, 8),
		}
		locksHeld.Store(id, locks)
	}

	return locks
}

func noteLock(l unsafe.Pointer) {
	locks := getGLocks()

	for _, lock := range locks.locksHeld {
		if lock == l {
			panic(fmt.Sprintf("Deadlock on goroutine %d! Double lock of %p: %+v", goid.Get(), l, locks))
		}
	}

	// Commit only after checking for panic conditions so that this lock
	// isn't on the list if the above panic is recovered.
	locks.locksHeld = append(locks.locksHeld, l)
}

func noteUnlock(l unsafe.Pointer) {
	locks := getGLocks()

	if len(locks.locksHeld) == 0 {
		panic(fmt.Sprintf("Unlock of %p on goroutine %d without any locks held! All locks:\n%s", l, goid.Get(), dumpLocks()))
	}

	// Search backwards since callers are most likely to unlock in LIFO order.
	length := len(locks.locksHeld)
	for i := length - 1; i >= 0; i-- {
		if l == locks.locksHeld[i] {
			copy(locks.locksHeld[i:length-1], locks.locksHeld[i+1:length])
			// Clear last entry to ensure addr can be GC'd.
			locks.locksHeld[length-1] = nil
			locks.locksHeld = locks.locksHeld[:length-1]
			return
		}
	}

	panic(fmt.Sprintf("Unlock of %p on goroutine %d without matching lock! All locks:\n%s", l, goid.Get(), dumpLocks()))
}

func dumpLocks() string {
	var s strings.Builder
	locksHeld.Range(func(key, value interface{}) bool {
		goid := key.(int64)
		locks := value.(*gLocks)

		// N.B. accessing gLocks of another G is fundamentally racy.

		fmt.Fprintf(&s, "goroutine %d:\n", goid)
		if len(locks.locksHeld) == 0 {
			fmt.Fprintf(&s, "\t<none>\n")
		}
		for _, lock := range locks.locksHeld {
			fmt.Fprintf(&s, "\t%p\n", lock)
		}
		fmt.Fprintf(&s, "\n")

		return true
	})

	return s.String()
}

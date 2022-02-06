// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2019 The gVisor Authors.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This is mostly copied from the standard library's sync/rwmutex.go.
//
// Happens-before relationships indicated to the race detector:
// - Unlock -> Lock (via writerSem)
// - Unlock -> RLock (via readerSem)
// - RUnlock -> Lock (via writerSem)
// - DowngradeLock -> RLock (via readerSem)

package sync

import (
	"sync/atomic"
	"unsafe"
)

// CrossGoroutineRWMutex is equivalent to RWMutex, but it need not be unlocked
// by a the same goroutine that locked the mutex.
type CrossGoroutineRWMutex struct {
	// w is held if there are pending writers
	//
	// We use CrossGoroutineMutex rather than Mutex because the lock
	// annotation instrumentation in Mutex will trigger false positives in
	// the race detector when called inside of RaceDisable.
	w           CrossGoroutineMutex
	writerSem   uint32 // semaphore for writers to wait for completing readers
	readerSem   uint32 // semaphore for readers to wait for completing writers
	readerCount int32  // number of pending readers
	readerWait  int32  // number of departing readers
}

const rwmutexMaxReaders = 1 << 30

// TryRLock locks rw for reading. It returns true if it succeeds and false
// otherwise. It does not block.
// +checklocksignore
func (rw *CrossGoroutineRWMutex) TryRLock() bool {
	if RaceEnabled {
		RaceDisable()
	}
	for {
		rc := atomic.LoadInt32(&rw.readerCount)
		if rc < 0 {
			if RaceEnabled {
				RaceEnable()
			}
			return false
		}
		if !atomic.CompareAndSwapInt32(&rw.readerCount, rc, rc+1) {
			continue
		}
		if RaceEnabled {
			RaceEnable()
			RaceAcquire(unsafe.Pointer(&rw.readerSem))
		}
		return true
	}
}

// RLock locks rw for reading.
//
// It should not be used for recursive read locking; a blocked Lock call
// excludes new readers from acquiring the lock. See the documentation on the
// RWMutex type.
// +checklocksignore
func (rw *CrossGoroutineRWMutex) RLock() {
	if RaceEnabled {
		RaceDisable()
	}
	if atomic.AddInt32(&rw.readerCount, 1) < 0 {
		// A writer is pending, wait for it.
		semacquire(&rw.readerSem)
	}
	if RaceEnabled {
		RaceEnable()
		RaceAcquire(unsafe.Pointer(&rw.readerSem))
	}
}

// RUnlock undoes a single RLock call.
//
// Preconditions:
// * rw is locked for reading.
// +checklocksignore
func (rw *CrossGoroutineRWMutex) RUnlock() {
	if RaceEnabled {
		RaceReleaseMerge(unsafe.Pointer(&rw.writerSem))
		RaceDisable()
	}
	if r := atomic.AddInt32(&rw.readerCount, -1); r < 0 {
		if r+1 == 0 || r+1 == -rwmutexMaxReaders {
			panic("RUnlock of unlocked RWMutex")
		}
		// A writer is pending.
		if atomic.AddInt32(&rw.readerWait, -1) == 0 {
			// The last reader unblocks the writer.
			semrelease(&rw.writerSem, false, 0)
		}
	}
	if RaceEnabled {
		RaceEnable()
	}
}

// TryLock locks rw for writing. It returns true if it succeeds and false
// otherwise. It does not block.
// +checklocksignore
func (rw *CrossGoroutineRWMutex) TryLock() bool {
	if RaceEnabled {
		RaceDisable()
	}
	// First, resolve competition with other writers.
	if !rw.w.TryLock() {
		if RaceEnabled {
			RaceEnable()
		}
		return false
	}
	// Only proceed if there are no readers.
	if !atomic.CompareAndSwapInt32(&rw.readerCount, 0, -rwmutexMaxReaders) {
		rw.w.Unlock()
		if RaceEnabled {
			RaceEnable()
		}
		return false
	}
	if RaceEnabled {
		RaceEnable()
		RaceAcquire(unsafe.Pointer(&rw.writerSem))
	}
	return true
}

// Lock locks rw for writing. If the lock is already locked for reading or
// writing, Lock blocks until the lock is available.
// +checklocksignore
func (rw *CrossGoroutineRWMutex) Lock() {
	if RaceEnabled {
		RaceDisable()
	}
	// First, resolve competition with other writers.
	rw.w.Lock()
	// Announce to readers there is a pending writer.
	r := atomic.AddInt32(&rw.readerCount, -rwmutexMaxReaders) + rwmutexMaxReaders
	// Wait for active readers.
	if r != 0 && atomic.AddInt32(&rw.readerWait, r) != 0 {
		semacquire(&rw.writerSem)
	}
	if RaceEnabled {
		RaceEnable()
		RaceAcquire(unsafe.Pointer(&rw.writerSem))
	}
}

// Unlock unlocks rw for writing.
//
// Preconditions:
// * rw is locked for writing.
// +checklocksignore
func (rw *CrossGoroutineRWMutex) Unlock() {
	if RaceEnabled {
		RaceRelease(unsafe.Pointer(&rw.writerSem))
		RaceRelease(unsafe.Pointer(&rw.readerSem))
		RaceDisable()
	}
	// Announce to readers there is no active writer.
	r := atomic.AddInt32(&rw.readerCount, rwmutexMaxReaders)
	if r >= rwmutexMaxReaders {
		panic("Unlock of unlocked RWMutex")
	}
	// Unblock blocked readers, if any.
	for i := 0; i < int(r); i++ {
		semrelease(&rw.readerSem, false, 0)
	}
	// Allow other writers to proceed.
	rw.w.Unlock()
	if RaceEnabled {
		RaceEnable()
	}
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
//
// Preconditions:
// * rw is locked for writing.
// +checklocksignore
func (rw *CrossGoroutineRWMutex) DowngradeLock() {
	if RaceEnabled {
		RaceRelease(unsafe.Pointer(&rw.readerSem))
		RaceDisable()
	}
	// Announce to readers there is no active writer and one additional reader.
	r := atomic.AddInt32(&rw.readerCount, rwmutexMaxReaders+1)
	if r >= rwmutexMaxReaders+1 {
		panic("DowngradeLock of unlocked RWMutex")
	}
	// Unblock blocked readers, if any. Note that this loop starts as 1 since r
	// includes this goroutine.
	for i := 1; i < int(r); i++ {
		semrelease(&rw.readerSem, false, 0)
	}
	// Allow other writers to proceed to rw.w.Lock(). Note that they will still
	// block on rw.writerSem since at least this reader exists, such that
	// DowngradeLock() is atomic with the previous write lock.
	rw.w.Unlock()
	if RaceEnabled {
		RaceEnable()
	}
}

// A RWMutex is a reader/writer mutual exclusion lock. The lock can be held by
// an arbitrary number of readers or a single writer. The zero value for a
// RWMutex is an unlocked mutex.
//
// A RWMutex must not be copied after first use.
//
// If a goroutine holds a RWMutex for reading and another goroutine might call
// Lock, no goroutine should expect to be able to acquire a read lock until the
// initial read lock is released. In particular, this prohibits recursive read
// locking. This is to ensure that the lock eventually becomes available; a
// blocked Lock call excludes new readers from acquiring the lock.
//
// A Mutex must be unlocked by the same goroutine that locked it. This
// invariant is enforced with the 'checklocks' build tag.
type RWMutex struct {
	m CrossGoroutineRWMutex
}

// TryRLock locks rw for reading. It returns true if it succeeds and false
// otherwise. It does not block.
// +checklocksignore
func (rw *RWMutex) TryRLock() bool {
	// Note lock first to enforce proper locking even if unsuccessful.
	noteLock(unsafe.Pointer(rw))
	locked := rw.m.TryRLock()
	if !locked {
		noteUnlock(unsafe.Pointer(rw))
	}
	return locked
}

// RLock locks rw for reading.
//
// It should not be used for recursive read locking; a blocked Lock call
// excludes new readers from acquiring the lock. See the documentation on the
// RWMutex type.
// +checklocksignore
func (rw *RWMutex) RLock() {
	noteLock(unsafe.Pointer(rw))
	rw.m.RLock()
}

// RUnlock undoes a single RLock call.
//
// Preconditions:
// * rw is locked for reading.
// * rw was locked by this goroutine.
// +checklocksignore
func (rw *RWMutex) RUnlock() {
	rw.m.RUnlock()
	noteUnlock(unsafe.Pointer(rw))
}

// TryLock locks rw for writing. It returns true if it succeeds and false
// otherwise. It does not block.
// +checklocksignore
func (rw *RWMutex) TryLock() bool {
	// Note lock first to enforce proper locking even if unsuccessful.
	noteLock(unsafe.Pointer(rw))
	locked := rw.m.TryLock()
	if !locked {
		noteUnlock(unsafe.Pointer(rw))
	}
	return locked
}

// Lock locks rw for writing. If the lock is already locked for reading or
// writing, Lock blocks until the lock is available.
// +checklocksignore
func (rw *RWMutex) Lock() {
	noteLock(unsafe.Pointer(rw))
	rw.m.Lock()
}

// Unlock unlocks rw for writing.
//
// Preconditions:
// * rw is locked for writing.
// * rw was locked by this goroutine.
// +checklocksignore
func (rw *RWMutex) Unlock() {
	rw.m.Unlock()
	noteUnlock(unsafe.Pointer(rw))
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
//
// Preconditions:
// * rw is locked for writing.
// +checklocksignore
func (rw *RWMutex) DowngradeLock() {
	// No note change for DowngradeLock.
	rw.m.DowngradeLock()
}

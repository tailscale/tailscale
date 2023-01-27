// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syncs

import (
	"sync"
)

// AssertLocked panics if m is not locked.
func AssertLocked(m *sync.Mutex) {
	if m.TryLock() {
		m.Unlock()
		panic("mutex is not locked")
	}
}

// AssertRLocked panics if rw is not locked for reading or writing.
func AssertRLocked(rw *sync.RWMutex) {
	if rw.TryLock() {
		rw.Unlock()
		panic("mutex is not locked")
	}
}

// AssertWLocked panics if rw is not locked for writing.
func AssertWLocked(rw *sync.RWMutex) {
	if rw.TryRLock() {
		rw.RUnlock()
		panic("mutex is not rlocked")
	}
}

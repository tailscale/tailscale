// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_tsync_test

package tsync

import (
	"fmt"
	"sync"
	"weak"
)

type Mutex struct {
	mu sync.Mutex
}

func (m *Mutex) Lock() {
	noteLock(m)
	m.mu.Lock()
}

func (m *Mutex) Unlock() {
	noteUnlock(m)
	m.mu.Unlock()
}

func (m *Mutex) TryLock() bool {
	locked := m.mu.TryLock()
	if locked {
		noteLock(m)
	}
	return locked
}

type lockInfo struct {
	locked bool
}

var (
	// TODO: this should be a per-G datastructure
	locksMu sync.Mutex
	locks   map[weak.Pointer[Mutex]]*lockInfo
)

func panicLocked(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)

	// First, gather all current (non-GCed) locks.
	type lockEntry struct {
		wp weak.Pointer[Mutex]
		li *lockInfo
	}
	var currLocks []lockEntry
	for wp, li := range locks {
		if wp.Value() != nil {
			currLocks = append(currLocks, lockEntry{wp, li})
		}
	}

	msg += fmt.Sprintf("\ncurrent locks (%d):", len(currLocks))
	for _, cl := range currLocks {
		if cl.li.locked {
			msg += fmt.Sprintf("\n\tlocked: %p", cl.wp.Value())
		} else {
			msg += fmt.Sprintf("\n\tunlocked: %p", cl.wp.Value())
		}
	}
	panic(msg)
}

func noteLock(m *Mutex) {
	locksMu.Lock()
	defer locksMu.Unlock()
	if locks == nil {
		locks = make(map[weak.Pointer[Mutex]]*lockInfo)
	}

	wp := weak.Make(m)
	li, ok := locks[wp]
	if !ok {
		locks[wp] = &lockInfo{
			locked: true,
		}
		return
	}

	li.locked = true

	// TODO: additional checks here
	// TODO: clear things out of the locks map when GCed
}

func noteUnlock(m *Mutex) {
	locksMu.Lock()
	defer locksMu.Unlock()

	wp := weak.Make(m)
	li, ok := locks[wp]
	if !ok {
		panicLocked("unknown Unlock on mutex %p", m)
	}

	li.locked = false

	// TODO: additional checks here
	// TODO: clear things out of the locks map when GCed
}

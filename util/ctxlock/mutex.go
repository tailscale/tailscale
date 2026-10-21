// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ctxlock

import (
	"sync"
)

// mutex is a wrapper around [sync.Mutex] that associates a [Rank] with the mutex
// and provides storage for an arbitrary value (of type S) to be used by the state
// that owns the lock while it is held. It's exported as [Mutex] in the package API.
type mutex[R Rank, S any] struct {
	// r is the rank of the mutex, used to check lock order.
	r R
	// m is the underlying mutex that provides the locking mechanism.
	m sync.Mutex
	// lockState is a memory region used by the state that owns the lock while it is held.
	// It serves as pre-allocated lockState to avoid (in the [unchecked] case)
	// or reduce (in the [checked] case) memory allocations.
	lockState S
}

func (m *mutex[R, S]) rank() Rank {
	return m.r
}

func (m *mutex[R, S]) lock() {
	m.m.Lock()
}

func (m *mutex[R, S]) state() any {
	return &m.lockState
}

func (m *mutex[R, S]) unlock() {
	m.m.Unlock()
}

// mutexHandle is a subset of the [mutex] methods that are used once the mutex is locked.
type mutexHandle interface {
	rank() Rank
	state() any
	unlock()
}

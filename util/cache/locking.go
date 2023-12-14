// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cache

import "sync"

// Locking wraps an inner Cache implementation with a mutex, making it
// safe for concurrent use. All methods are serialized on the same mutex.
type Locking[K comparable, V any, C Cache[K, V]] struct {
	sync.Mutex
	inner C
}

// NewLocking creates a new Locking cache wrapping inner.
func NewLocking[K comparable, V any, C Cache[K, V]](inner C) *Locking[K, V, C] {
	return &Locking[K, V, C]{inner: inner}
}

// Get implements Cache.
//
// The cache's mutex is held for the entire duration of this function,
// including while the FillFunc is being called. This function is not
// reentrant; attempting to call Get from a FillFunc will deadlock.
func (c *Locking[K, V, C]) Get(key K, f FillFunc[V]) (V, error) {
	c.Lock()
	defer c.Unlock()
	return c.inner.Get(key, f)
}

// Forget implements Cache.
func (c *Locking[K, V, C]) Forget(key K) {
	c.Lock()
	defer c.Unlock()
	c.inner.Forget(key)
}

// Empty implements Cache.
func (c *Locking[K, V, C]) Empty() {
	c.Lock()
	defer c.Unlock()
	c.inner.Empty()
}

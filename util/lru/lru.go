// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package lru contains a typed Least-Recently-Used cache.
package lru

import (
	"container/list"
)

// Cache is container type keyed by K, storing V, optionally evicting the least
// recently used items if a maximum size is exceeded.
//
// The zero value is valid to use.
//
// It is not safe for concurrent access.
//
// The current implementation is just the traditional LRU linked list; a future
// implementation may be more advanced to avoid pathological cases.
type Cache[K comparable, V any] struct {
	// MaxEntries is the maximum number of cache entries before
	// an item is evicted. Zero means no limit.
	MaxEntries int

	ll *list.List
	m  map[K]*list.Element // of *entry[K,V]
}

// entry is the element type for the container/list.Element.
type entry[K comparable, V any] struct {
	key   K
	value V
}

// Set adds or replaces a value to the cache, set or updating its associated
// value.
//
// If MaxEntries is non-zero and the length of the cache is greater
// after any addition, the least recently used value is evicted.
func (c *Cache[K, V]) Set(key K, value V) {
	if c.m == nil {
		c.m = make(map[K]*list.Element)
		c.ll = list.New()
	}
	if ee, ok := c.m[key]; ok {
		c.ll.MoveToFront(ee)
		ee.Value.(*entry[K, V]).value = value
		return
	}
	ele := c.ll.PushFront(&entry[K, V]{key, value})
	c.m[key] = ele
	if c.MaxEntries != 0 && c.Len() > c.MaxEntries {
		c.DeleteOldest()
	}
}

// Get looks up a key's value from the cache, returning either
// the value or the zero value if it not present.
//
// If found, key is moved to the front of the LRU.
func (c *Cache[K, V]) Get(key K) V {
	v, _ := c.GetOk(key)
	return v
}

// Contains reports whether c contains key.
//
// If found, key is moved to the front of the LRU.
func (c *Cache[K, V]) Contains(key K) bool {
	_, ok := c.GetOk(key)
	return ok
}

// GetOk looks up a key's value from the cache, also reporting
// whether it was present.
//
// If found, key is moved to the front of the LRU.
func (c *Cache[K, V]) GetOk(key K) (value V, ok bool) {
	if ele, hit := c.m[key]; hit {
		c.ll.MoveToFront(ele)
		return ele.Value.(*entry[K, V]).value, true
	}
	var zero V
	return zero, false
}

// PeekOk looks up the key's value from the cache, also reporting
// whether it was present.
//
// Unlike GetOk, PeekOk does not move key to the front of the
// LRU. This should mostly be used for non-intrusive debug inspection
// of the cache.
func (c *Cache[K, V]) PeekOk(key K) (value V, ok bool) {
	if ele, hit := c.m[key]; hit {
		return ele.Value.(*entry[K, V]).value, true
	}
	var zero V
	return zero, false
}

// Delete removes the provided key from the cache if it was present.
func (c *Cache[K, V]) Delete(key K) {
	if e, ok := c.m[key]; ok {
		c.deleteElement(e)
	}
}

// DeleteOldest removes the item from the cache that was least recently
// accessed. It is a no-op if the cache is empty.
func (c *Cache[K, V]) DeleteOldest() {
	if c.ll != nil {
		if e := c.ll.Back(); e != nil {
			c.deleteElement(e)
		}
	}
}

func (c *Cache[K, V]) deleteElement(e *list.Element) {
	c.ll.Remove(e)
	delete(c.m, e.Value.(*entry[K, V]).key)
}

// Len returns the number of items in the cache.
func (c *Cache[K, V]) Len() int { return len(c.m) }

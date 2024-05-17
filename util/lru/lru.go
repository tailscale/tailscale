// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package lru contains a typed Least-Recently-Used cache.
package lru

import (
	"fmt"
	"html"
	"io"
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

	// head is a ring of LRU values. head points to the most recently
	// used element, head.prev is the least recently used.
	//
	// An LRU is technically a simple list rather than a ring, but
	// implementing it as a ring makes the list manipulation
	// operations more regular, because the first/last positions in
	// the list stop being special.
	//
	// head is nil when the LRU is empty.
	head *entry[K, V]
	// lookup is a map of all the LRU entries contained in
	// head. lookup and head always contain exactly the same elements;
	// lookup is just there to allow O(1) lookups of keys.
	lookup map[K]*entry[K, V]
}

// entry is an entry of Cache.
type entry[K comparable, V any] struct {
	prev, next *entry[K, V]
	key        K
	value      V
}

// Set adds or replaces a value to the cache, set or updating its associated
// value.
//
// If MaxEntries is non-zero and the length of the cache is greater
// after any addition, the least recently used value is evicted.
func (c *Cache[K, V]) Set(key K, value V) {
	if c.lookup == nil {
		c.lookup = make(map[K]*entry[K, V])
	}
	if ent, ok := c.lookup[key]; ok {
		c.moveToFront(ent)
		ent.value = value
		return
	}
	ent := c.newAtFront(key, value)
	c.lookup[key] = ent
	if c.MaxEntries != 0 && c.Len() > c.MaxEntries {
		c.deleteOldest()
	}
}

// Clear removes all items from the cache.
func (c *Cache[K, V]) Clear() {
	c.head = nil
	c.lookup = nil
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

// GetOk looks up a key's value from the cache, also reporting whether
// it was present.
//
// If found, key is moved to the front of the LRU.
func (c *Cache[K, V]) GetOk(key K) (value V, ok bool) {
	if ent, hit := c.lookup[key]; hit {
		c.moveToFront(ent)
		return ent.value, true
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
	if ent, hit := c.lookup[key]; hit {
		return ent.value, true
	}
	var zero V
	return zero, false
}

// Delete removes the provided key from the cache if it was present.
func (c *Cache[K, V]) Delete(key K) {
	if ent, ok := c.lookup[key]; ok {
		c.deleteElement(ent)
	}
}

// DeleteOldest removes the item from the cache that was least
// recently accessed. It is a no-op if the cache is empty.
func (c *Cache[K, V]) DeleteOldest() {
	if c.head != nil {
		c.deleteOldest()
	}
}

// Len returns the number of items in the cache.
func (c *Cache[K, V]) Len() int { return len(c.lookup) }

// newAtFront creates a new LRU entry using key and value, and inserts
// it at the front of c.head.
func (c *Cache[K, V]) newAtFront(key K, value V) *entry[K, V] {
	ret := &entry[K, V]{key: key, value: value}
	if c.head == nil {
		ret.prev = ret
		ret.next = ret
	} else {
		ret.next = c.head
		ret.prev = c.head.prev
		c.head.prev.next = ret
		c.head.prev = ret
	}
	c.head = ret
	return ret
}

// moveToFront moves ent, which must be an existing element of the
// cache, to the front of c.head.
func (c *Cache[K, V]) moveToFront(ent *entry[K, V]) {
	if c.head == ent {
		return
	}
	ent.prev.next = ent.next
	ent.next.prev = ent.prev
	ent.prev = c.head.prev
	ent.next = c.head
	c.head.prev.next = ent
	c.head.prev = ent
	c.head = ent
}

// deleteOldest removes the oldest entry in the cache. It panics if
// there are no entries in the cache.
func (c *Cache[K, V]) deleteOldest() { c.deleteElement(c.head.prev) }

// deleteElement removes ent from the cache. ent must be an existing
// current element of the cache.
func (c *Cache[K, V]) deleteElement(ent *entry[K, V]) {
	if ent.next == ent {
		c.head = nil
	} else {
		ent.next.prev = ent.prev
		ent.prev.next = ent.next
		if c.head == ent {
			c.head = ent.next
		}
	}
	delete(c.lookup, ent.key)
}

// ForEach calls fn for each entry in the cache, from most recently
// used to least recently used.
func (c *Cache[K, V]) ForEach(fn func(K, V)) {
	if c.head == nil {
		return
	}
	cur := c.head
	for {
		fn(cur.key, cur.value)
		cur = cur.next
		if cur == c.head {
			return
		}
	}
}

// DumpHTML writes the state of the cache to the given writer,
// formatted as an HTML table.
func (c *Cache[K, V]) DumpHTML(w io.Writer) {
	io.WriteString(w, "<table><tr><th>Key</th><th>Value</th></tr>")
	c.ForEach(func(k K, v V) {
		kStr := html.EscapeString(fmt.Sprint(k))
		vStr := html.EscapeString(fmt.Sprint(v))
		fmt.Fprintf(w, "<tr><td>%s</td><td>%v</td></tr>", kStr, vStr)
	})
	io.WriteString(w, "</table>")
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
//
// Original implementation (from same author) from which this was derived was:
// https://github.com/golang/groupcache/blob/5b532d6fd5efaf7fa130d4e859a2fde0fc3a9e1b/lru/lru.go
// ... which was Apache licensed:
// https://github.com/golang/groupcache/blob/master/LICENSE

// Package flowtrack contains types for tracking TCP/UDP flows by 4-tuples.
package flowtrack

import (
	"container/list"
	"fmt"
	"net/netip"

	"tailscale.com/types/ipproto"
)

// Tuple is a 5-tuple of proto, source and destination IP and port.
type Tuple struct {
	Proto ipproto.Proto  `json:"proto"`
	Src   netip.AddrPort `json:"src"`
	Dst   netip.AddrPort `json:"dst"`
}

func (t Tuple) String() string {
	return fmt.Sprintf("(%v %v => %v)", t.Proto, t.Src, t.Dst)
}

// Cache is an LRU cache keyed by Tuple.
//
// The zero value is valid to use.
//
// It is not safe for concurrent access.
type Cache[Value any] struct {
	// MaxEntries is the maximum number of cache entries before
	// an item is evicted. Zero means no limit.
	MaxEntries int

	ll *list.List
	m  map[Tuple]*list.Element // of *entry
}

// entry is the container/list element type.
type entry[Value any] struct {
	key   Tuple
	value Value
}

// Add adds a value to the cache, set or updating its associated
// value.
//
// If MaxEntries is non-zero and the length of the cache is greater
// after any addition, the least recently used value is evicted.
func (c *Cache[Value]) Add(key Tuple, value Value) {
	if c.m == nil {
		c.m = make(map[Tuple]*list.Element)
		c.ll = list.New()
	}
	if ee, ok := c.m[key]; ok {
		c.ll.MoveToFront(ee)
		ee.Value.(*entry[Value]).value = value
		return
	}
	ele := c.ll.PushFront(&entry[Value]{key, value})
	c.m[key] = ele
	if c.MaxEntries != 0 && c.Len() > c.MaxEntries {
		c.RemoveOldest()
	}
}

// Get looks up a key's value from the cache, also reporting
// whether it was present.
func (c *Cache[Value]) Get(key Tuple) (value *Value, ok bool) {
	if ele, hit := c.m[key]; hit {
		c.ll.MoveToFront(ele)
		return &ele.Value.(*entry[Value]).value, true
	}
	return nil, false
}

// Remove removes the provided key from the cache if it was present.
func (c *Cache[Value]) Remove(key Tuple) {
	if ele, hit := c.m[key]; hit {
		c.removeElement(ele)
	}
}

// RemoveOldest removes the oldest item from the cache, if any.
func (c *Cache[Value]) RemoveOldest() {
	if c.ll != nil {
		if ele := c.ll.Back(); ele != nil {
			c.removeElement(ele)
		}
	}
}

func (c *Cache[Value]) removeElement(e *list.Element) {
	c.ll.Remove(e)
	delete(c.m, e.Value.(*entry[Value]).key)
}

// Len returns the number of items in the cache.
func (c *Cache[Value]) Len() int { return len(c.m) }

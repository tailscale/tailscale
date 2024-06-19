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
	"encoding/json"
	"fmt"
	"net/netip"

	"tailscale.com/types/ipproto"
)

// MakeTuple makes a Tuple out of netip.AddrPort values.
func MakeTuple(proto ipproto.Proto, src, dst netip.AddrPort) Tuple {
	return Tuple{
		proto:   proto,
		src:     src.Addr().As16(),
		srcPort: src.Port(),
		dst:     dst.Addr().As16(),
		dstPort: dst.Port(),
	}
}

// Tuple is a 5-tuple of proto, source and destination IP and port.
//
// This struct originally used netip.AddrPort, but that was about twice as slow
// when used as a map key due to the alignment and extra space for the IPv6 zone
// pointers (unneeded for all our current 2024-06-17 flowtrack needs).
//
// This struct is packed optimally and doesn't contain gaps or pointers.
type Tuple struct {
	src     [16]byte
	dst     [16]byte
	srcPort uint16
	dstPort uint16
	proto   ipproto.Proto
}

func (t Tuple) SrcAddr() netip.Addr {
	return netip.AddrFrom16(t.src).Unmap()
}

func (t Tuple) DstAddr() netip.Addr {
	return netip.AddrFrom16(t.dst).Unmap()
}

func (t Tuple) SrcPort() uint16 { return t.srcPort }
func (t Tuple) DstPort() uint16 { return t.dstPort }

func (t Tuple) String() string {
	return fmt.Sprintf("(%v %v => %v)", t.proto,
		netip.AddrPortFrom(t.SrcAddr(), t.srcPort),
		netip.AddrPortFrom(t.DstAddr(), t.dstPort))
}

func (t Tuple) MarshalJSON() ([]byte, error) {
	return json.Marshal(tupleOld{
		Proto: t.proto,
		Src:   netip.AddrPortFrom(t.SrcAddr(), t.srcPort),
		Dst:   netip.AddrPortFrom(t.DstAddr(), t.dstPort),
	})
}

func (t *Tuple) UnmarshalJSON(b []byte) error {
	var ot tupleOld
	if err := json.Unmarshal(b, &ot); err != nil {
		return err
	}
	*t = MakeTuple(ot.Proto, ot.Src, ot.Dst)
	return nil
}

// tupleOld is the old JSON representation of Tuple, before
// we split and rearranged the fields for efficiency. This type
// is the JSON adapter type to make sure we still generate
// the same JSON as before.
type tupleOld struct {
	Proto ipproto.Proto  `json:"proto"`
	Src   netip.AddrPort `json:"src"`
	Dst   netip.AddrPort `json:"dst"`
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

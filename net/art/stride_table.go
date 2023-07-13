// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package art

import (
	"bytes"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"strconv"
	"strings"
)

// strideEntry is a strideTable entry.
type strideEntry[T any] struct {
	// prefixIndex is the prefixIndex(...) value that caused this stride entry's
	// value to be populated, or 0 if value is nil.
	//
	// We need to keep track of this because allot() uses it to determine
	// whether an entry was propagated from a parent entry, or if it's a
	// different independent route.
	prefixIndex int
	// value is the value associated with the strideEntry, if any.
	value *T
	// child is the child strideTable associated with the strideEntry, if any.
	child *strideTable[T]
}

// strideTable is a binary tree that implements an 8-bit routing table.
//
// The leaves of the binary tree are host routes (/8s). Each parent is a
// successively larger prefix that encompasses its children (/7 through /0).
type strideTable[T any] struct {
	// prefix is the prefix represented by the 0/0 route of this strideTable. It
	// is used in multi-level tables to support path compression.
	prefix netip.Prefix
	// entries is the nodes of the binary tree, laid out in a flattened array.
	//
	// The array indices are arranged by the prefixIndex function, such that the
	// parent of the node at index i is located at index i>>1, and its children
	// at indices i<<1 and (i<<1)+1.
	//
	// A few consequences of this arrangement: host routes (/8) occupy the last
	// 256 entries in the table; the single default route /0 is at index 1, and
	// index 0 is unused (in the original paper, it's hijacked through sneaky C
	// memory trickery to store the refcount, but this is Go, where we don't
	// store random bits in pointers lest we confuse the GC)
	entries [lastHostIndex + 1]strideEntry[T]
	// routeRefs is the number of route entries in this table.
	routeRefs uint16
	// childRefs is the number of child strideTables referenced by this table.
	childRefs uint16
}

const (
	// firstHostIndex is the array index of the first host route. This is hostIndex(0/8).
	firstHostIndex = 0b1_0000_0000
	// lastHostIndex is the array index of the last host route. This is hostIndex(0xFF/8).
	lastHostIndex = 0b1_1111_1111
)

// getChild returns the child strideTable pointer for addr (if any), and an
// internal array index that can be used with deleteChild.
func (t *strideTable[T]) getChild(addr uint8) (child *strideTable[T], idx int) {
	idx = hostIndex(addr)
	return t.entries[idx].child, idx
}

// deleteChild deletes the child strideTable at idx (if any). idx should be
// obtained via a call to getChild.
func (t *strideTable[T]) deleteChild(idx int) {
	t.entries[idx].child = nil
	t.childRefs--
}

// setChild replaces the child strideTable for addr (if any) with child.
func (t *strideTable[T]) setChild(addr uint8, child *strideTable[T]) {
	idx := hostIndex(addr)
	if t.entries[idx].child == nil {
		t.childRefs++
	}
	t.entries[idx].child = child
}

// setChildByIdx replaces the child strideTable at idx (if any) with
// child. idx should be obtained via a call to getChild.
func (t *strideTable[T]) setChildByIdx(idx int, child *strideTable[T]) {
	if t.entries[idx].child == nil {
		t.childRefs++
	}
	t.entries[idx].child = child
}

// getOrCreateChild returns the child strideTable for addr, creating it if
// necessary.
func (t *strideTable[T]) getOrCreateChild(addr uint8) (child *strideTable[T], created bool) {
	idx := hostIndex(addr)
	if t.entries[idx].child == nil {
		t.entries[idx].child = &strideTable[T]{
			prefix: childPrefixOf(t.prefix, addr),
		}
		t.childRefs++
		return t.entries[idx].child, true
	}
	return t.entries[idx].child, false
}

// getValAndChild returns both the prefix and child strideTable for
// addr. Both returned values can be nil if no entry of that type
// exists for addr.
func (t *strideTable[T]) getValAndChild(addr uint8) (*T, *strideTable[T]) {
	idx := hostIndex(addr)
	return t.entries[idx].value, t.entries[idx].child
}

// findFirstChild returns the first non-nil child strideTable in t, or
// nil if t has no children.
func (t *strideTable[T]) findFirstChild() *strideTable[T] {
	for i := firstHostIndex; i <= lastHostIndex; i++ {
		if child := t.entries[i].child; child != nil {
			return child
		}
	}
	return nil
}

// allot updates entries whose stored prefixIndex matches oldPrefixIndex, in the
// subtree rooted at idx. Matching entries have their stored prefixIndex set to
// newPrefixIndex, and their value set to val.
//
// allot is the core of the ART algorithm, enabling efficient insertion/deletion
// while preserving very fast lookups.
func (t *strideTable[T]) allot(idx int, oldPrefixIndex, newPrefixIndex int, val *T) {
	if t.entries[idx].prefixIndex != oldPrefixIndex {
		// current prefixIndex isn't what we expect. This is a recursive call
		// that found a child subtree that already has a more specific route
		// installed. Don't touch it.
		return
	}
	t.entries[idx].value = val
	t.entries[idx].prefixIndex = newPrefixIndex
	if idx >= firstHostIndex {
		// The entry we just updated was a host route, we're at the bottom of
		// the binary tree.
		return
	}
	// Propagate the allotment to this node's children.
	left := idx << 1
	t.allot(left, oldPrefixIndex, newPrefixIndex, val)
	right := left + 1
	t.allot(right, oldPrefixIndex, newPrefixIndex, val)
}

// insert adds the route addr/prefixLen to t, with value val.
func (t *strideTable[T]) insert(addr uint8, prefixLen int, val *T) {
	idx := prefixIndex(addr, prefixLen)
	old := t.entries[idx].value
	oldIdx := t.entries[idx].prefixIndex
	if oldIdx == idx && old == val {
		// This exact prefix+value is already in the table.
		return
	}
	t.allot(idx, oldIdx, idx, val)
	if oldIdx != idx {
		// This route entry was freshly created (not just updated), that's a new
		// reference.
		t.routeRefs++
	}
	return
}

// delete removes the route addr/prefixLen from t.
func (t *strideTable[T]) delete(addr uint8, prefixLen int) *T {
	idx := prefixIndex(addr, prefixLen)
	recordedIdx := t.entries[idx].prefixIndex
	if recordedIdx != idx {
		// Route entry doesn't exist
		return nil
	}
	val := t.entries[idx].value

	parentIdx := idx >> 1
	t.allot(idx, idx, t.entries[parentIdx].prefixIndex, t.entries[parentIdx].value)
	t.routeRefs--
	return val
}

// get does a route lookup for addr and returns the associated value, or nil if
// no route matched.
func (t *strideTable[T]) get(addr uint8) *T {
	return t.entries[hostIndex(addr)].value
}

// TableDebugString returns the contents of t, formatted as a table with one
// line per entry.
func (t *strideTable[T]) tableDebugString() string {
	var ret bytes.Buffer
	for i, ent := range t.entries {
		if i == 0 {
			continue
		}
		v := "(nil)"
		if ent.value != nil {
			v = fmt.Sprint(*ent.value)
		}
		fmt.Fprintf(&ret, "idx=%3d (%s), parent=%3d (%s), val=%v\n", i, formatPrefixTable(inversePrefixIndex(i)), ent.prefixIndex, formatPrefixTable(inversePrefixIndex((ent.prefixIndex))), v)
	}
	return ret.String()
}

// treeDebugString returns the contents of t, formatted as a sparse tree. Each
// line is one entry, indented such that it is contained by all its parents, and
// non-overlapping with any of its siblings.
func (t *strideTable[T]) treeDebugString() string {
	var ret bytes.Buffer
	t.treeDebugStringRec(&ret, 1, 0) // index of 0/0, and 0 indent
	return ret.String()
}

func (t *strideTable[T]) treeDebugStringRec(w io.Writer, idx, indent int) {
	addr, len := inversePrefixIndex(idx)
	if t.entries[idx].prefixIndex != 0 && t.entries[idx].prefixIndex == idx {
		fmt.Fprintf(w, "%s%d/%d (%d/%d) = %v\n", strings.Repeat(" ", indent), addr, len, addr, len, *t.entries[idx].value)
		indent += 2
	}
	if idx >= firstHostIndex {
		return
	}
	left := idx << 1
	t.treeDebugStringRec(w, left, indent)
	right := left + 1
	t.treeDebugStringRec(w, right, indent)
}

// prefixIndex returns the array index of the tree node for addr/prefixLen.
func prefixIndex(addr uint8, prefixLen int) int {
	// the prefixIndex of addr/prefixLen is the prefixLen most significant bits
	// of addr, with a 1 tacked onto the left-hand side. For example:
	//
	//   - 0/0 is 1: 0 bits of the addr, with a 1 tacked on
	//   - 42/8 is 1_00101010 (298): all bits of 42, with a 1 tacked on
	//   - 48/4 is 1_0011 (19): 4 most-significant bits of 48, with a 1 tacked on
	return (int(addr) >> (8 - prefixLen)) + (1 << prefixLen)
}

// hostIndex returns the array index of the host route for addr.
// It is equivalent to prefixIndex(addr, 8).
func hostIndex(addr uint8) int {
	return int(addr) + 1<<8
}

// inversePrefixIndex returns the address and prefix length of idx. It is the
// inverse of prefixIndex. Only used for debugging and in tests.
func inversePrefixIndex(idx int) (addr uint8, len int) {
	lz := bits.LeadingZeros(uint(idx))
	len = strconv.IntSize - lz - 1
	addr = uint8(idx&(0xFF>>(8-len))) << (8 - len)
	return addr, len
}

// formatPrefixTable formats addr and len as addr/len, with a constant width
// suitable for use in table formatting.
func formatPrefixTable(addr uint8, len int) string {
	if len < 0 { // this happens for inversePrefixIndex(0)
		return "<nil>"
	}
	return fmt.Sprintf("%3d/%d", addr, len)
}

// childPrefixOf returns the child prefix of parent whose final byte
// is stride. The parent prefix must be byte-aligned
// (i.e. parent.Bits() must be a multiple of 8), and be no more
// specific than /24 for IPv4 or /120 for IPv6.
//
// For example, childPrefixOf("192.168.0.0/16", 8) == "192.168.8.0/24".
func childPrefixOf(parent netip.Prefix, stride uint8) netip.Prefix {
	l := parent.Bits()
	if l%8 != 0 {
		panic("parent prefix is not 8-bit aligned")
	}
	if l >= parent.Addr().BitLen() {
		panic("parent prefix cannot be extended further")
	}
	off := l / 8
	if parent.Addr().Is4() {
		bs := parent.Addr().As4()
		bs[off] = stride
		return netip.PrefixFrom(netip.AddrFrom4(bs), l+8)
	} else {
		bs := parent.Addr().As16()
		bs[off] = stride
		return netip.PrefixFrom(netip.AddrFrom16(bs), l+8)
	}
}

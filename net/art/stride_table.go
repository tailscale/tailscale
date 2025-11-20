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

const (
	debugStrideInsert = false
	debugStrideDelete = false
)

// strideTable is a binary tree that implements an 8-bit routing table.
//
// The leaves of the binary tree are host routes (/8s). Each parent is a
// successively larger prefix that encompasses its children (/7 through /0).
type strideTable[T any] struct {
	// prefix is the prefix represented by the 0/0 route of this
	// strideTable. It is used in multi-level tables to support path
	// compression. All strideTables must have a valid prefix
	// (non-zero value, passes IsValid()) whose length is a multiple
	// of 8 (e.g. /8, /16, but not /15).
	prefix netip.Prefix
	// entries is the nodes of the binary tree, laid out in a flattened array.
	//
	// The array indices are arranged by the prefixIndex function, such that the
	// parent of the node at index i is located at index i>>1, and its children
	// at indices i<<1 and (i<<1)+1.
	//
	// A few consequences of this arrangement: host routes (/8) occupy
	// the last numChildren entries in the table; the single default
	// route /0 is at index 1, and index 0 is unused (in the original
	// paper, it's hijacked through sneaky C memory trickery to store
	// the refcount, but this is Go, where we don't store random bits
	// in pointers lest we confuse the GC)
	//
	// A nil value means no route matches the queried route.
	entries [lastHostIndex + 1]*T
	// children are the child tables of this table. Each child
	// represents the address space within one of this table's host
	// routes (/8).
	children [numChildren]*strideTable[T]
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

	// numChildren is the maximum number of child tables a strideTable can hold.
	numChildren = 256
)

// getChild returns the child strideTable pointer for addr, or nil if none.
func (t *strideTable[T]) getChild(addr uint8) *strideTable[T] {
	return t.children[addr]
}

// deleteChild deletes the child strideTable at addr. It is valid to
// delete a non-existent child.
func (t *strideTable[T]) deleteChild(addr uint8) {
	if t.children[addr] != nil {
		t.childRefs--
	}
	t.children[addr] = nil
}

// setChild sets the child strideTable for addr to child.
func (t *strideTable[T]) setChild(addr uint8, child *strideTable[T]) {
	if t.children[addr] == nil {
		t.childRefs++
	}
	t.children[addr] = child
}

// getOrCreateChild returns the child strideTable for addr, creating it if
// necessary.
func (t *strideTable[T]) getOrCreateChild(addr uint8) (child *strideTable[T], created bool) {
	ret := t.children[addr]
	if ret == nil {
		ret = &strideTable[T]{
			prefix: childPrefixOf(t.prefix, addr),
		}
		t.children[addr] = ret
		t.childRefs++
		return ret, true
	}
	return ret, false
}

// findFirstChild returns the first child strideTable in t, or nil if
// t has no children.
func (t *strideTable[T]) findFirstChild() *strideTable[T] {
	for _, child := range t.children {
		if child != nil {
			return child
		}
	}
	return nil
}

// hasPrefixRootedAt reports whether t.entries[idx] is the root node of
// a prefix.
func (t *strideTable[T]) hasPrefixRootedAt(idx int) bool {
	val := t.entries[idx]
	if val == nil {
		return false
	}

	parentIdx := parentIndex(idx)
	if parentIdx == 0 {
		// idx is non-nil, and is at the 0/0 route position.
		return true
	}
	if parent := t.entries[parentIdx]; val != parent {
		// parent node in the tree isn't the same prefix, so idx must
		// be a root.
		return true
	}
	return false
}

// allot updates entries whose stored prefixIndex matches oldPrefixIndex, in the
// subtree rooted at idx. Matching entries have their stored prefixIndex set to
// newPrefixIndex, and their value set to val.
//
// allot is the core of the ART algorithm, enabling efficient insertion/deletion
// while preserving very fast lookups.
func (t *strideTable[T]) allot(idx int, old, new *T) {
	if t.entries[idx] != old {
		// current idx isn't what we expect. This is a recursive call
		// that found a child subtree that already has a more specific
		// route installed. Don't touch it.
		return
	}
	t.entries[idx] = new
	if idx >= firstHostIndex {
		// The entry we just updated was a host route, we're at the bottom of
		// the binary tree.
		return
	}
	// Propagate the allotment to this node's children.
	left := idx << 1
	t.allot(left, old, new)
	right := left + 1
	t.allot(right, old, new)
}

// insert adds the route addr/prefixLen to t, with value val.
func (t *strideTable[T]) insert(addr uint8, prefixLen int, val T) {
	idx := prefixIndex(addr, prefixLen)
	if !t.hasPrefixRootedAt(idx) {
		// This route entry is being freshly created (not just
		// updated), that's a new reference.
		t.routeRefs++
	}

	old := t.entries[idx]

	// For allot to work correctly, each distinct prefix in the
	// strideTable must have a different value pointer, even if val is
	// identical. This new()+assignment guarantees that each inserted
	// prefix gets a unique address.
	p := new(T)
	*p = val

	t.allot(idx, old, p)
	return
}

// delete removes the route addr/prefixLen from t. Reports whether the
// prefix existed in the table prior to deletion.
func (t *strideTable[T]) delete(addr uint8, prefixLen int) (wasPresent bool) {
	idx := prefixIndex(addr, prefixLen)
	if !t.hasPrefixRootedAt(idx) {
		// Route entry doesn't exist
		return false
	}

	val := t.entries[idx]
	var parentVal *T
	if parentIdx := parentIndex(idx); parentIdx != 0 {
		parentVal = t.entries[parentIdx]
	}

	t.allot(idx, val, parentVal)
	t.routeRefs--
	return true
}

// get does a route lookup for addr and (value, true) if a matching
// route exists, or (zero, false) otherwise.
func (t *strideTable[T]) get(addr uint8) (ret T, ok bool) {
	if val := t.entries[hostIndex(addr)]; val != nil {
		return *val, true
	}
	return ret, false
}

// getValAndChild returns both the prefix value and child strideTable
// for addr. valOK reports whether a prefix value exists for addr, and
// child is non-nil if a child exists for addr.
func (t *strideTable[T]) getValAndChild(addr uint8) (val T, valOK bool, child *strideTable[T]) {
	vp := t.entries[hostIndex(addr)]
	if vp != nil {
		val = *vp
		valOK = true
	}
	child = t.children[addr]
	return
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
		if ent != nil {
			v = fmt.Sprint(*ent)
		}
		fmt.Fprintf(&ret, "idx=%3d (%s), val=%v\n", i, formatPrefixTable(inversePrefixIndex(i)), v)
	}
	return ret.String()
}

func (t *strideTable[T]) treeDebugStringRec(w io.Writer, idx, indent int) {
	addr, len := inversePrefixIndex(idx)
	if t.hasPrefixRootedAt(idx) {
		fmt.Fprintf(w, "%s%d/%d (%02x/%d) = %v\n", strings.Repeat(" ", indent), addr, len, addr, len, *t.entries[idx])
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

// parentIndex returns the index of idx's parent prefix, or 0 if idx
// is the index of 0/0.
func parentIndex(idx int) int {
	return idx >> 1
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
	ln := parent.Bits()
	if ln%8 != 0 {
		panic("parent prefix is not 8-bit aligned")
	}
	if ln >= parent.Addr().BitLen() {
		panic("parent prefix cannot be extended further")
	}
	off := ln / 8
	if parent.Addr().Is4() {
		bs := parent.Addr().As4()
		bs[off] = stride
		return netip.PrefixFrom(netip.AddrFrom4(bs), ln+8)
	} else {
		bs := parent.Addr().As16()
		bs[off] = stride
		return netip.PrefixFrom(netip.AddrFrom16(bs), ln+8)
	}
}

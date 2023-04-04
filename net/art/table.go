// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package art provides a routing table that implements the Allotment Routing
// Table (ART) algorithm by Donald Knuth, as described in the paper by Yoichi
// Hariguchi.
//
// ART outperforms the traditional radix tree implementations for route lookups,
// insertions, and deletions.
//
// For more information, see Yoichi Hariguchi's paper:
// https://cseweb.ucsd.edu//~varghese/TEACH/cs228/artlookup.pdf
package art

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// Table is an IPv4 and IPv6 routing table.
type Table[T any] struct {
	v4 strideTable[T]
	v6 strideTable[T]
}

// Get does a route lookup for addr and returns the associated value, or nil if
// no route matched.
func (t *Table[T]) Get(addr netip.Addr) *T {
	st := &t.v4
	if addr.Is6() {
		st = &t.v6
	}

	var ret *T
	for _, stride := range addr.AsSlice() {
		rt, child := st.getValAndChild(stride)
		if rt != nil {
			// Found a more specific route than whatever we found previously,
			// keep a note.
			ret = rt
		}
		if child == nil {
			// No sub-routes further down, whatever we have recorded in ret is
			// the result.
			return ret
		}
		st = child
	}

	// Unreachable because Insert/Delete won't allow the leaf strideTables to
	// have children, so we must return via the nil check in the loop.
	panic("unreachable")
}

// Insert adds pfx to the table, with value val.
// If pfx is already present in the table, its value is set to val.
func (t *Table[T]) Insert(pfx netip.Prefix, val *T) {
	if val == nil {
		panic("Table.Insert called with nil value")
	}
	st := &t.v4
	if pfx.Addr().Is6() {
		st = &t.v6
	}
	bs := pfx.Addr().AsSlice()
	i := 0
	numBits := pfx.Bits()

	// The strideTable we want to insert into is potentially at the end of a
	// chain of parent tables, each one encoding successive 8 bits of the
	// prefix. Navigate downwards, allocating child tables as needed, until we
	// find the one this prefix belongs in.
	for numBits > 8 {
		st = st.getOrCreateChild(bs[i])
		i++
		numBits -= 8
	}
	// Finally, insert the remaining 0-8 bits of the prefix into the child
	// table.
	st.insert(bs[i], numBits, val)
}

// Delete removes pfx from the table, if it is present.
func (t *Table[T]) Delete(pfx netip.Prefix) {
	st := &t.v4
	if pfx.Addr().Is6() {
		st = &t.v6
	}
	bs := pfx.Addr().AsSlice()
	i := 0
	numBits := pfx.Bits()

	// Deletion may drive the refcount of some strideTables down to zero. We
	// need to clean up these dangling tables, so we have to keep track of which
	// tables we touch on the way down, and which strideEntry index each child
	// is registered in.
	strideTables := [16]*strideTable[T]{st}
	var strideIndexes [16]int

	// Similar to Insert, navigate down the tree of strideTables, looking for
	// the one that houses the last 0-8 bits of the prefix to delete.
	//
	// The only difference is that here, we don't create missing child tables.
	// If a child necessary to pfx is missing, then the pfx cannot exist in the
	// Table, and we can exit early.
	for numBits > 8 {
		child, idx := st.getChild(bs[i])
		if child == nil {
			// Prefix can't exist in the table, one of the necessary
			// strideTables doesn't exit.
			return
		}
		// Note that the strideIndex and strideTables entries are off-by-one.
		// The child table pointer is recorded at i+1, but it is referenced by a
		// particular index in the parent table, at index i.
		strideIndexes[i] = idx
		i++
		strideTables[i] = child
		numBits -= 8
		st = child
	}
	if st.delete(bs[i], numBits) == nil {
		// Prefix didn't exist in the expected strideTable, refcount hasn't
		// changed, no need to run through cleanup.
		return
	}

	// st.delete reduced st's refcount by one, so we may be hanging onto a chain
	// of redundant strideTables. Walk back up the path we recorded in the
	// descent loop, deleting tables until we encounter one that still has other
	// refs (or we hit the root strideTable, which is never deleted).
	for i > 0 && strideTables[i].refs == 0 {
		strideTables[i-1].deleteChild(strideIndexes[i-1])
		i--
	}
}

// debugSummary prints the tree of allocated strideTables in t, with each
// strideTable's refcount.
func (t *Table[T]) debugSummary() string {
	var ret bytes.Buffer
	fmt.Fprintf(&ret, "v4: ")
	strideSummary(&ret, &t.v4, 0)
	fmt.Fprintf(&ret, "v6: ")
	strideSummary(&ret, &t.v6, 0)
	return ret.String()
}

func strideSummary[T any](w io.Writer, st *strideTable[T], indent int) {
	fmt.Fprintf(w, "%d refs\n", st.refs)
	indent += 2
	for i := firstHostIndex; i <= lastHostIndex; i++ {
		if child := st.entries[i].child; child != nil {
			addr, len := inversePrefixIndex(i)
			fmt.Fprintf(w, "%s%d/%d: ", strings.Repeat(" ", indent), addr, len)
			strideSummary(w, child, indent)
		}
	}
}

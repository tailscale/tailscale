// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package pool contains a generic type for managing a pool of resources; for
// example, connections to a database, or to a remote service.
//
// Unlike sync.Pool from the Go standard library, this pool does not remove
// items from the pool when garbage collection happens, nor is it safe for
// concurrent use like sync.Pool.
package pool

import (
	"fmt"
	"math/rand/v2"

	"tailscale.com/types/ptr"
)

// consistencyCheck enables additional runtime checks to ensure that the pool
// is well-formed; it is disabled by default, and can be enabled during tests
// to catch additional bugs.
const consistencyCheck = false

// Pool is a pool of resources. It is not safe for concurrent use.
type Pool[V any] struct {
	s []itemAndIndex[V]
}

type itemAndIndex[V any] struct {
	// item is the element in the pool
	item V

	// index is the current location of this item in pool.s. It gets set to
	// -1 when the item is removed from the pool.
	index *int
}

// Handle is an opaque handle to a resource in a pool. It is used to delete an
// item from the pool, without requiring the item to be comparable.
type Handle[V any] struct {
	idx *int // pointer to index; -1 if not in slice
}

// Len returns the current size of the pool.
func (p *Pool[V]) Len() int {
	return len(p.s)
}

// Clear removes all items from the pool.
func (p *Pool[V]) Clear() {
	p.s = nil
}

// AppendTakeAll removes all items from the pool, appending them to the
// provided slice (which can be nil) and returning them. The returned slice can
// be nil if the provided slice was nil and the pool was empty.
//
// This function does not free the backing storage for the pool; to do that,
// use the Clear function.
func (p *Pool[V]) AppendTakeAll(dst []V) []V {
	ret := dst
	for i := range p.s {
		e := p.s[i]
		if consistencyCheck && e.index == nil {
			panic(fmt.Sprintf("pool: index is nil at %d", i))
		}
		if *e.index >= 0 {
			ret = append(ret, p.s[i].item)
		}
	}
	p.s = p.s[:0]
	return ret
}

// Add adds an item to the pool and returns a handle to it. The handle can be
// used to delete the item from the pool with the Delete method.
func (p *Pool[V]) Add(item V) Handle[V] {
	// Store the index in a pointer, so that we can pass it to both the
	// handle and store it in the itemAndIndex.
	idx := ptr.To(len(p.s))
	p.s = append(p.s, itemAndIndex[V]{
		item:  item,
		index: idx,
	})
	return Handle[V]{idx}
}

// Peek will return the item with the given handle without removing it from the
// pool.
//
// It will return ok=false if the item has been deleted or previously taken.
func (p *Pool[V]) Peek(h Handle[V]) (v V, ok bool) {
	p.checkHandle(h)
	idx := *h.idx
	if idx < 0 {
		var zero V
		return zero, false
	}
	p.checkIndex(idx)
	return p.s[idx].item, true
}

// Delete removes the item from the pool.
//
// It reports whether the element was deleted; it will return false if the item
// has been taken with the TakeRandom function, or if the item was already
// deleted.
func (p *Pool[V]) Delete(h Handle[V]) bool {
	p.checkHandle(h)
	idx := *h.idx
	if idx < 0 {
		return false
	}
	p.deleteIndex(idx)
	return true
}

func (p *Pool[V]) deleteIndex(idx int) {
	// Mark the item as deleted.
	p.checkIndex(idx)
	*(p.s[idx].index) = -1

	// If this isn't the last element in the slice, overwrite the element
	// at this item's index with the last element.
	lastIdx := len(p.s) - 1

	if idx < lastIdx {
		last := p.s[lastIdx]
		p.checkElem(lastIdx, last)
		*last.index = idx
		p.s[idx] = last
	}

	// Zero out last element (for GC) and truncate slice.
	p.s[lastIdx] = itemAndIndex[V]{}
	p.s = p.s[:lastIdx]
}

// Take will remove the item with the given handle from the pool and return it.
//
// It will return ok=false and the zero value if the item has been deleted or
// previously taken.
func (p *Pool[V]) Take(h Handle[V]) (v V, ok bool) {
	p.checkHandle(h)
	idx := *h.idx
	if idx < 0 {
		var zero V
		return zero, false
	}

	e := p.s[idx]
	p.deleteIndex(idx)
	return e.item, true
}

// TakeRandom returns and removes a random element from p
// and reports whether there was one to take.
//
// It will return ok=false and the zero value if the pool is empty.
func (p *Pool[V]) TakeRandom() (v V, ok bool) {
	if len(p.s) == 0 {
		var zero V
		return zero, false
	}
	pick := rand.IntN(len(p.s))
	e := p.s[pick]
	p.checkElem(pick, e)
	p.deleteIndex(pick)
	return e.item, true
}

// checkIndex verifies that the provided index is within the bounds of the
// pool's slice, and that the corresponding element has a non-nil index
// pointer, and panics if not.
func (p *Pool[V]) checkIndex(idx int) {
	if !consistencyCheck {
		return
	}

	if idx >= len(p.s) {
		panic(fmt.Sprintf("pool: index %d out of range (len %d)", idx, len(p.s)))
	}
	if p.s[idx].index == nil {
		panic(fmt.Sprintf("pool: index is nil at %d", idx))
	}
}

// checkHandle verifies that the provided handle is not nil, and panics if it
// is.
func (p *Pool[V]) checkHandle(h Handle[V]) {
	if !consistencyCheck {
		return
	}

	if h.idx == nil {
		panic("pool: nil handle")
	}
}

// checkElem verifies that the provided itemAndIndex has a non-nil index, and
// that the stored index matches the expected position within the slice.
func (p *Pool[V]) checkElem(idx int, e itemAndIndex[V]) {
	if !consistencyCheck {
		return
	}

	if e.index == nil {
		panic("pool: index is nil")
	}
	if got := *e.index; got != idx {
		panic(fmt.Sprintf("pool: index is incorrect: want %d, got %d", idx, got))
	}
}

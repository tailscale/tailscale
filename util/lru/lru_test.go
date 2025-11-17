// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lru

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/util/slicesx"
)

func TestLRU(t *testing.T) {
	var c Cache[int, string]
	c.Set(1, "one")
	c.Set(2, "two")
	if g, w := c.Get(1), "one"; g != w {
		t.Errorf("got %q; want %q", g, w)
	}
	if g, w := c.Get(2), "two"; g != w {
		t.Errorf("got %q; want %q", g, w)
	}
	c.DeleteOldest()
	if g, w := c.Get(1), ""; g != w {
		t.Errorf("got %q; want %q", g, w)
	}
	if g, w := c.Len(), 1; g != w {
		t.Errorf("Len = %d; want %d", g, w)
	}
	c.MaxEntries = 2
	c.Set(1, "one")
	c.Set(2, "two")
	c.Set(3, "three")
	if c.Contains(1) {
		t.Errorf("contains 1; should not")
	}
	if !c.Contains(2) {
		t.Errorf("doesn't contain 2; should")
	}
	if !c.Contains(3) {
		t.Errorf("doesn't contain 3; should")
	}
	c.Delete(3)
	if c.Contains(3) {
		t.Errorf("contains 3; should not")
	}
	c.Clear()
	if g, w := c.Len(), 0; g != w {
		t.Errorf("Len = %d; want %d", g, w)
	}
}

func TestLRUDeleteCorruption(t *testing.T) {
	// Regression test for tailscale/corp#14747

	c := Cache[int, bool]{}

	c.Set(1, true)
	c.Set(2, true) // now 2 is the head
	c.Delete(2)    // delete the head
	c.check(t)
}

func TestStressEvictions(t *testing.T) {
	const (
		cacheSize = 1_000
		numKeys   = 10_000
		numProbes = 100_000
	)

	vm := map[uint64]bool{}
	for len(vm) < numKeys {
		vm[rand.Uint64()] = true
	}
	vals := slicesx.MapKeys(vm)

	c := Cache[uint64, bool]{
		MaxEntries: cacheSize,
	}

	for range numProbes {
		v := vals[rand.Intn(len(vals))]
		c.Set(v, true)
		if ln := c.Len(); ln > cacheSize {
			t.Fatalf("Cache size now %d, want max %d", ln, cacheSize)
		}
	}
}

func TestStressBatchedEvictions(t *testing.T) {
	// One of Cache's consumers dynamically adjusts the cache size at
	// runtime, and does batched evictions as needed. This test
	// simulates that behavior.

	const (
		cacheSizeMin = 1_000
		cacheSizeMax = 2_000
		numKeys      = 10_000
		numProbes    = 100_000
	)

	vm := map[uint64]bool{}
	for len(vm) < numKeys {
		vm[rand.Uint64()] = true
	}
	vals := slicesx.MapKeys(vm)

	c := Cache[uint64, bool]{}

	for range numProbes {
		v := vals[rand.Intn(len(vals))]
		c.Set(v, true)
		if c.Len() == cacheSizeMax {
			// Batch eviction down to cacheSizeMin
			for c.Len() > cacheSizeMin {
				c.DeleteOldest()
			}
		}
		if ln := c.Len(); ln > cacheSizeMax {
			t.Fatalf("Cache size now %d, want max %d", ln, cacheSizeMax)
		}
	}
}

func TestLRUStress(t *testing.T) {
	var c Cache[int, int]
	const (
		maxSize   = 500
		numProbes = 5_000
	)
	for range numProbes {
		n := rand.Intn(maxSize * 2)
		op := rand.Intn(4)
		switch op {
		case 0:
			c.Get(n)
		case 1:
			c.Set(n, n)
		case 2:
			c.Delete(n)
		case 3:
			for c.Len() > maxSize {
				c.DeleteOldest()
			}
		}
		c.check(t)
	}
}

// check verifies that c.lookup and c.head are consistent in size with
// each other, and that the ring has the same size when traversed in
// both directions.
func (c *Cache[K, V]) check(t testing.TB) {
	size := c.Len()
	nextLen := c.nextLen(t, size)
	prevLen := c.prevLen(t, size)
	if nextLen != size {
		t.Fatalf("next list len %v != map len %v", nextLen, size)
	}
	if prevLen != size {
		t.Fatalf("prev list len %v != map len %v", prevLen, size)
	}
}

// nextLen returns the length of the ring at c.head when traversing
// the .next pointers.
func (c *Cache[K, V]) nextLen(t testing.TB, limit int) (n int) {
	if c.head == nil {
		return 0
	}
	n = 1
	at := c.head.next
	for at != c.head {
		limit--
		if limit < 0 {
			t.Fatal("next list is too long")
		}
		n++
		at = at.next
	}
	return n
}

// prevLen returns the length of the ring at c.head when traversing
// the .prev pointers.
func (c *Cache[K, V]) prevLen(t testing.TB, limit int) (n int) {
	if c.head == nil {
		return 0
	}
	n = 1
	at := c.head.prev
	for at != c.head {
		limit--
		if limit < 0 {
			t.Fatal("next list is too long")
		}
		n++
		at = at.prev
	}
	return n
}

func TestDumpHTML(t *testing.T) {
	c := Cache[int, string]{MaxEntries: 3}

	c.Set(1, "foo")
	c.Set(2, "bar")
	c.Set(3, "qux")
	c.Set(4, "wat")

	var out bytes.Buffer
	c.DumpHTML(&out)

	want := strings.Join([]string{
		"<table>",
		"<tr><th>Key</th><th>Value</th></tr>",
		"<tr><td>4</td><td>wat</td></tr>",
		"<tr><td>3</td><td>qux</td></tr>",
		"<tr><td>2</td><td>bar</td></tr>",
		"</table>",
	}, "")

	if diff := cmp.Diff(out.String(), want); diff != "" {
		t.Fatalf("wrong DumpHTML output (-got+want):\n%s", diff)
	}
}

func BenchmarkLRU(b *testing.B) {
	const lruSize = 10
	const maxval = 15 // 33% more keys than the LRU can hold

	c := Cache[int, bool]{MaxEntries: lruSize}
	b.ReportAllocs()
	for range b.N {
		k := rand.Intn(maxval)
		if !c.Get(k) {
			c.Set(k, true)
		}
	}
}

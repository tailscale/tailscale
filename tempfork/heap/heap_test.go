// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package heap

import (
	"math/rand"
	"testing"

	"golang.org/x/exp/constraints"
)

type myHeap[T constraints.Ordered] []T

func (h *myHeap[T]) Less(i, j int) bool {
	return (*h)[i] < (*h)[j]
}

func (h *myHeap[T]) Swap(i, j int) {
	(*h)[i], (*h)[j] = (*h)[j], (*h)[i]
}

func (h *myHeap[T]) Len() int {
	return len(*h)
}

func (h *myHeap[T]) Pop() (v T) {
	*h, v = (*h)[:h.Len()-1], (*h)[h.Len()-1]
	return
}

func (h *myHeap[T]) Push(v T) {
	*h = append(*h, v)
}

func (h myHeap[T]) verify(t *testing.T, i int) {
	t.Helper()
	n := h.Len()
	j1 := 2*i + 1
	j2 := 2*i + 2
	if j1 < n {
		if h.Less(j1, i) {
			t.Errorf("heap invariant invalidated [%d] = %v > [%d] = %v", i, h[i], j1, h[j1])
			return
		}
		h.verify(t, j1)
	}
	if j2 < n {
		if h.Less(j2, i) {
			t.Errorf("heap invariant invalidated [%d] = %v > [%d] = %v", i, h[i], j1, h[j2])
			return
		}
		h.verify(t, j2)
	}
}

func TestInit0(t *testing.T) {
	h := new(myHeap[int])
	for i := 20; i > 0; i-- {
		h.Push(0) // all elements are the same
	}
	Init[int](h)
	h.verify(t, 0)

	for i := 1; h.Len() > 0; i++ {
		x := Pop[int](h)
		h.verify(t, 0)
		if x != 0 {
			t.Errorf("%d.th pop got %d; want %d", i, x, 0)
		}
	}
}

func TestInit1(t *testing.T) {
	h := new(myHeap[int])
	for i := 20; i > 0; i-- {
		h.Push(i) // all elements are different
	}
	Init[int](h)
	h.verify(t, 0)

	for i := 1; h.Len() > 0; i++ {
		x := Pop[int](h)
		h.verify(t, 0)
		if x != i {
			t.Errorf("%d.th pop got %d; want %d", i, x, i)
		}
	}
}

func Test(t *testing.T) {
	h := new(myHeap[int])
	h.verify(t, 0)

	for i := 20; i > 10; i-- {
		h.Push(i)
	}
	Init[int](h)
	h.verify(t, 0)

	for i := 10; i > 0; i-- {
		Push[int](h, i)
		h.verify(t, 0)
	}

	for i := 1; h.Len() > 0; i++ {
		x := Pop[int](h)
		if i < 20 {
			Push[int](h, 20+i)
		}
		h.verify(t, 0)
		if x != i {
			t.Errorf("%d.th pop got %d; want %d", i, x, i)
		}
	}
}

func TestRemove0(t *testing.T) {
	h := new(myHeap[int])
	for i := range 10 {
		h.Push(i)
	}
	h.verify(t, 0)

	for h.Len() > 0 {
		i := h.Len() - 1
		x := Remove[int](h, i)
		if x != i {
			t.Errorf("Remove(%d) got %d; want %d", i, x, i)
		}
		h.verify(t, 0)
	}
}

func TestRemove1(t *testing.T) {
	h := new(myHeap[int])
	for i := range 10 {
		h.Push(i)
	}
	h.verify(t, 0)

	for i := 0; h.Len() > 0; i++ {
		x := Remove[int](h, 0)
		if x != i {
			t.Errorf("Remove(0) got %d; want %d", x, i)
		}
		h.verify(t, 0)
	}
}

func TestRemove2(t *testing.T) {
	N := 10

	h := new(myHeap[int])
	for i := range N {
		h.Push(i)
	}
	h.verify(t, 0)

	m := make(map[int]bool)
	for h.Len() > 0 {
		m[Remove[int](h, (h.Len()-1)/2)] = true
		h.verify(t, 0)
	}

	if len(m) != N {
		t.Errorf("len(m) = %d; want %d", len(m), N)
	}
	for i := range len(m) {
		if !m[i] {
			t.Errorf("m[%d] doesn't exist", i)
		}
	}
}

func BenchmarkDup(b *testing.B) {
	const n = 10000
	h := make(myHeap[int], 0, n)
	for range b.N {
		for j := 0; j < n; j++ {
			Push[int](&h, 0) // all elements are the same
		}
		for h.Len() > 0 {
			Pop[int](&h)
		}
	}
}

func TestFix(t *testing.T) {
	h := new(myHeap[int])
	h.verify(t, 0)

	for i := 200; i > 0; i -= 10 {
		Push[int](h, i)
	}
	h.verify(t, 0)

	if (*h)[0] != 10 {
		t.Fatalf("Expected head to be 10, was %d", (*h)[0])
	}
	(*h)[0] = 210
	Fix[int](h, 0)
	h.verify(t, 0)

	for i := 100; i > 0; i-- {
		elem := rand.Intn(h.Len())
		if i&1 == 0 {
			(*h)[elem] *= 2
		} else {
			(*h)[elem] /= 2
		}
		Fix[int](h, elem)
		h.verify(t, 0)
	}
}

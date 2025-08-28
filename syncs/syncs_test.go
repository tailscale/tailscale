// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syncs

import (
	"context"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestAtomicValue(t *testing.T) {
	{
		// Always wrapping should not allocate for simple values
		// because wrappedValue[T] has the same memory layout as T.
		var v AtomicValue[bool]
		bools := []bool{true, false}
		if n := int(testing.AllocsPerRun(1000, func() {
			for _, b := range bools {
				v.Store(b)
			}
		})); n != 0 {
			t.Errorf("AllocsPerRun = %d, want 0", n)
		}
	}

	{
		var v AtomicValue[int]
		got, gotOk := v.LoadOk()
		if got != 0 || gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (0, false)", got, gotOk)
		}
		v.Store(1)
		got, gotOk = v.LoadOk()
		if got != 1 || !gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (1, true)", got, gotOk)
		}
	}

	{
		var v AtomicValue[error]
		got, gotOk := v.LoadOk()
		if got != nil || gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (nil, false)", got, gotOk)
		}
		v.Store(io.EOF)
		got, gotOk = v.LoadOk()
		if got != io.EOF || !gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (EOF, true)", got, gotOk)
		}
		err := &os.PathError{}
		v.Store(err)
		got, gotOk = v.LoadOk()
		if got != err || !gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (%v, true)", got, gotOk, err)
		}
		v.Store(nil)
		got, gotOk = v.LoadOk()
		if got != nil || !gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (nil, true)", got, gotOk)
		}
	}

	{
		c1, c2, c3 := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var v AtomicValue[chan struct{}]
		if v.CompareAndSwap(c1, c2) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if v.CompareAndSwap(nil, c1) != true {
			t.Fatalf("CompareAndSwap = false, want true")
		}
		if v.CompareAndSwap(c2, c3) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if v.CompareAndSwap(c1, c2) != true {
			t.Fatalf("CompareAndSwap = false, want true")
		}
	}
}

func TestMutexValue(t *testing.T) {
	var v MutexValue[time.Time]
	if n := int(testing.AllocsPerRun(1000, func() {
		v.Store(v.Load())
		v.WithLock(func(*time.Time) {})
	})); n != 0 {
		t.Errorf("AllocsPerRun = %d, want 0", n)
	}

	now := time.Now()
	v.Store(now)
	if !v.Load().Equal(now) {
		t.Errorf("Load = %v, want %v", v.Load(), now)
	}

	var group sync.WaitGroup
	var v2 MutexValue[int]
	var sum int
	for i := range 10 {
		group.Go(func() {
			old1 := v2.Load()
			old2 := v2.Swap(old1 + i)
			delta := old2 - old1
			v2.WithLock(func(p *int) { *p += delta })
		})
		sum += i
	}
	group.Wait()
	if v2.Load() != sum {
		t.Errorf("Load = %v, want %v", v2.Load(), sum)
	}
}

func TestWaitGroupChan(t *testing.T) {
	wg := NewWaitGroupChan()

	wantNotDone := func() {
		t.Helper()
		select {
		case <-wg.DoneChan():
			t.Fatal("done too early")
		default:
		}
	}

	wantDone := func() {
		t.Helper()
		select {
		case <-wg.DoneChan():
		default:
			t.Fatal("expected to be done")
		}
	}

	wg.Add(2)
	wantNotDone()

	wg.Decr()
	wantNotDone()

	wg.Decr()
	wantDone()
	wantDone()
}

func TestClosedChan(t *testing.T) {
	ch := ClosedChan()
	for range 2 {
		select {
		case <-ch:
		default:
			t.Fatal("not closed")
		}
	}
}

func TestSemaphore(t *testing.T) {
	s := NewSemaphore(2)
	s.Acquire()
	if !s.TryAcquire() {
		t.Fatal("want true")
	}
	if s.TryAcquire() {
		t.Fatal("want false")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.AcquireContext(ctx) {
		t.Fatal("want false")
	}
	s.Release()
	if !s.AcquireContext(context.Background()) {
		t.Fatal("want true")
	}
	s.Release()
	s.Release()
}

func TestMap(t *testing.T) {
	var m Map[string, int]
	if v, ok := m.Load("noexist"); v != 0 || ok {
		t.Errorf(`Load("noexist") = (%v, %v), want (0, false)`, v, ok)
	}
	m.LoadFunc("noexist", func(v int, ok bool) {
		if v != 0 || ok {
			t.Errorf(`LoadFunc("noexist") = (%v, %v), want (0, false)`, v, ok)
		}
	})
	m.Store("one", 1)
	if v, ok := m.LoadOrStore("one", -1); v != 1 || !ok {
		t.Errorf(`LoadOrStore("one", 1) = (%v, %v), want (1, true)`, v, ok)
	}
	if v, ok := m.Load("one"); v != 1 || !ok {
		t.Errorf(`Load("one") = (%v, %v), want (1, true)`, v, ok)
	}
	m.LoadFunc("one", func(v int, ok bool) {
		if v != 1 || !ok {
			t.Errorf(`LoadFunc("one") = (%v, %v), want (1, true)`, v, ok)
		}
	})
	if v, ok := m.LoadOrStore("two", 2); v != 2 || ok {
		t.Errorf(`LoadOrStore("two", 2) = (%v, %v), want (2, false)`, v, ok)
	}
	if v, ok := m.LoadOrInit("three", func() int { return 3 }); v != 3 || ok {
		t.Errorf(`LoadOrInit("three", 3) = (%v, %v), want (3, true)`, v, ok)
	}
	got := map[string]int{}
	want := map[string]int{"one": 1, "two": 2, "three": 3}
	for k, v := range m.All() {
		got[k] = v
	}
	if d := cmp.Diff(got, want); d != "" {
		t.Errorf("Range mismatch (-got +want):\n%s", d)
	}
	if v, ok := m.LoadAndDelete("two"); v != 2 || !ok {
		t.Errorf(`LoadAndDelete("two) = (%v, %v), want (2, true)`, v, ok)
	}
	if v, ok := m.LoadAndDelete("two"); v != 0 || ok {
		t.Errorf(`LoadAndDelete("two) = (%v, %v), want (0, false)`, v, ok)
	}
	m.Delete("three")
	m.Delete("one")
	m.Delete("noexist")
	got = map[string]int{}
	want = map[string]int{}
	for k, v := range m.All() {
		got[k] = v
	}
	if d := cmp.Diff(got, want); d != "" {
		t.Errorf("Range mismatch (-got +want):\n%s", d)
	}

	t.Run("LoadOrStore", func(t *testing.T) {
		var m Map[string, string]
		var wg sync.WaitGroup
		var ok1, ok2 bool
		wg.Go(func() { _, ok1 = m.LoadOrStore("", "") })
		wg.Go(func() { _, ok2 = m.LoadOrStore("", "") })
		wg.Wait()
		if ok1 == ok2 {
			t.Errorf("exactly one LoadOrStore should load")
		}
	})

	t.Run("Clear", func(t *testing.T) {
		var m Map[string, string]
		_, _ = m.LoadOrStore("a", "1")
		_, _ = m.LoadOrStore("b", "2")
		_, _ = m.LoadOrStore("c", "3")
		_, _ = m.LoadOrStore("d", "4")
		_, _ = m.LoadOrStore("e", "5")

		if m.Len() != 5 {
			t.Errorf("Len after loading want=5 got=%d", m.Len())
		}

		m.Clear()
		if m.Len() != 0 {
			t.Errorf("Len after Clear want=0 got=%d", m.Len())
		}
	})

	t.Run("Swap", func(t *testing.T) {
		var m Map[string, string]
		m.Store("hello", "world")
		if got, want := m.Swap("hello", "world2"), "world"; got != want {
			t.Errorf("got old value %q, want %q", got, want)
		}
		if got := m.Swap("empty", "foo"); got != "" {
			t.Errorf("got old value %q, want empty string", got)
		}
	})
}

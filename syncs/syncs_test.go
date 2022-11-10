// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syncs

import (
	"context"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

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
	for i := 0; i < 2; i++ {
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
	m.Store("one", 1)
	if v, ok := m.LoadOrStore("one", -1); v != 1 || !ok {
		t.Errorf(`LoadOrStore("one", 1) = (%v, %v), want (1, true)`, v, ok)
	}
	if v, ok := m.Load("one"); v != 1 || !ok {
		t.Errorf(`Load("one") = (%v, %v), want (1, true)`, v, ok)
	}
	if v, ok := m.LoadOrStore("two", 2); v != 2 || ok {
		t.Errorf(`LoadOrStore("two", 2) = (%v, %v), want (2, false)`, v, ok)
	}
	got := map[string]int{}
	want := map[string]int{"one": 1, "two": 2}
	m.Range(func(k string, v int) bool {
		got[k] = v
		return true
	})
	if d := cmp.Diff(got, want); d != "" {
		t.Errorf("Range mismatch (-got +want):\n%s", d)
	}
	if v, ok := m.LoadAndDelete("two"); v != 2 || !ok {
		t.Errorf(`LoadAndDelete("two) = (%v, %v), want (2, true)`, v, ok)
	}
	if v, ok := m.LoadAndDelete("two"); v != 0 || ok {
		t.Errorf(`LoadAndDelete("two) = (%v, %v), want (0, false)`, v, ok)
	}
	m.Delete("one")
	m.Delete("noexist")
	got = map[string]int{}
	want = map[string]int{}
	m.Range(func(k string, v int) bool {
		got[k] = v
		return true
	})
	if d := cmp.Diff(got, want); d != "" {
		t.Errorf("Range mismatch (-got +want):\n%s", d)
	}

	t.Run("LoadOrStore", func(t *testing.T) {
		var m Map[string, string]
		var wg sync.WaitGroup
		wg.Add(2)
		var ok1, ok2 bool
		go func() {
			defer wg.Done()
			_, ok1 = m.LoadOrStore("", "")
		}()
		go func() {
			defer wg.Done()
			_, ok2 = m.LoadOrStore("", "")
		}()
		wg.Wait()

		if ok1 == ok2 {
			t.Errorf("exactly one LoadOrStore should load")
		}
	})
}

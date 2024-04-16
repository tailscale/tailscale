// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lazy

import (
	"errors"
	"sync"
	"testing"
)

func TestSyncValue(t *testing.T) {
	var lt SyncValue[int]
	n := int(testing.AllocsPerRun(1000, func() {
		got := lt.Get(fortyTwo)
		if got != 42 {
			t.Fatalf("got %v; want 42", got)
		}
	}))
	if n != 0 {
		t.Errorf("allocs = %v; want 0", n)
	}
}

func TestSyncValueErr(t *testing.T) {
	var lt SyncValue[int]
	n := int(testing.AllocsPerRun(1000, func() {
		got, err := lt.GetErr(func() (int, error) {
			return 42, nil
		})
		if got != 42 || err != nil {
			t.Fatalf("got %v, %v; want 42, nil", got, err)
		}
	}))
	if n != 0 {
		t.Errorf("allocs = %v; want 0", n)
	}

	var lterr SyncValue[int]
	wantErr := errors.New("test error")
	n = int(testing.AllocsPerRun(1000, func() {
		got, err := lterr.GetErr(func() (int, error) {
			return 0, wantErr
		})
		if got != 0 || err != wantErr {
			t.Fatalf("got %v, %v; want 0, %v", got, err, wantErr)
		}
	}))
	if n != 0 {
		t.Errorf("allocs = %v; want 0", n)
	}
}

func TestSyncValueSet(t *testing.T) {
	var lt SyncValue[int]
	if !lt.Set(42) {
		t.Fatalf("Set failed")
	}
	if lt.Set(43) {
		t.Fatalf("Set succeeded after first Set")
	}
	n := int(testing.AllocsPerRun(1000, func() {
		got := lt.Get(fortyTwo)
		if got != 42 {
			t.Fatalf("got %v; want 42", got)
		}
	}))
	if n != 0 {
		t.Errorf("allocs = %v; want 0", n)
	}
}

func TestSyncValueMustSet(t *testing.T) {
	var lt SyncValue[int]
	lt.MustSet(42)
	defer func() {
		if e := recover(); e == nil {
			t.Errorf("unexpected success; want panic")
		}
	}()
	lt.MustSet(43)
}

func TestSyncValueConcurrent(t *testing.T) {
	var (
		lt       SyncValue[int]
		wg       sync.WaitGroup
		start    = make(chan struct{})
		routines = 10000
	)
	wg.Add(routines)
	for range routines {
		go func() {
			defer wg.Done()
			// Every goroutine waits for the go signal, so that more of them
			// have a chance to race on the initial Get than with sequential
			// goroutine starts.
			<-start
			got := lt.Get(fortyTwo)
			if got != 42 {
				t.Errorf("got %v; want 42", got)
			}
		}()
	}
	close(start)
	wg.Wait()
}

func TestSyncFunc(t *testing.T) {
	f := SyncFunc(fortyTwo)

	n := int(testing.AllocsPerRun(1000, func() {
		got := f()
		if got != 42 {
			t.Fatalf("got %v; want 42", got)
		}
	}))
	if n != 0 {
		t.Errorf("allocs = %v; want 0", n)
	}
}

func TestSyncFuncErr(t *testing.T) {
	f := SyncFuncErr(func() (int, error) {
		return 42, nil
	})
	n := int(testing.AllocsPerRun(1000, func() {
		got, err := f()
		if got != 42 || err != nil {
			t.Fatalf("got %v, %v; want 42, nil", got, err)
		}
	}))
	if n != 0 {
		t.Errorf("allocs = %v; want 0", n)
	}

	wantErr := errors.New("test error")
	f = SyncFuncErr(func() (int, error) {
		return 0, wantErr
	})
	n = int(testing.AllocsPerRun(1000, func() {
		got, err := f()
		if got != 0 || err != wantErr {
			t.Fatalf("got %v, %v; want 0, %v", got, err, wantErr)
		}
	}))
	if n != 0 {
		t.Errorf("allocs = %v; want 0", n)
	}
}

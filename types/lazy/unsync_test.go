// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lazy

import (
	"errors"
	"testing"
)

func fortyTwo() int { return 42 }

func TestGValue(t *testing.T) {
	var lt GValue[int]
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

func TestGValueErr(t *testing.T) {
	var lt GValue[int]
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

	var lterr GValue[int]
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

func TestGValueSet(t *testing.T) {
	var lt GValue[int]
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

func TestGValueMustSet(t *testing.T) {
	var lt GValue[int]
	lt.MustSet(42)
	defer func() {
		if e := recover(); e == nil {
			t.Errorf("unexpected success; want panic")
		}
	}()
	lt.MustSet(43)
}

func TestGValueRecursivePanic(t *testing.T) {
	defer func() {
		if e := recover(); e != nil {
			t.Logf("got panic, as expected")
		} else {
			t.Errorf("unexpected success; want panic")
		}
	}()
	v := GValue[int]{}
	v.Get(func() int {
		return v.Get(func() int { return 42 })
	})
}

func TestGFunc(t *testing.T) {
	f := GFunc(fortyTwo)

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

func TestGFuncErr(t *testing.T) {
	f := GFuncErr(func() (int, error) {
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
	f = GFuncErr(func() (int, error) {
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

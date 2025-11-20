// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lazy

import (
	"errors"
	"testing"
)

func TestGMap(t *testing.T) {
	var gm GMap[string, int]
	n := int(testing.AllocsPerRun(1000, func() {
		got := gm.Get("42", fortyTwo)
		if got != 42 {
			t.Fatalf("got %v; want 42", got)
		}
	}))
	if n != 0 {
		t.Errorf("allocs = %v; want 0", n)
	}
}

func TestGMapErr(t *testing.T) {
	var gm GMap[string, int]
	n := int(testing.AllocsPerRun(1000, func() {
		got, err := gm.GetErr("42", func() (int, error) {
			return 42, nil
		})
		if got != 42 || err != nil {
			t.Fatalf("got %v, %v; want 42, nil", got, err)
		}
	}))
	if n != 0 {
		t.Errorf("allocs = %v; want 0", n)
	}

	var gmErr GMap[string, int]
	wantErr := errors.New("test error")
	n = int(testing.AllocsPerRun(1000, func() {
		got, err := gmErr.GetErr("42", func() (int, error) {
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

func TestGMapSet(t *testing.T) {
	var gm GMap[string, int]
	if !gm.Set("42", 42) {
		t.Fatalf("Set failed")
	}
	if gm.Set("42", 43) {
		t.Fatalf("Set succeeded after first Set")
	}
	n := int(testing.AllocsPerRun(1000, func() {
		got := gm.Get("42", fortyTwo)
		if got != 42 {
			t.Fatalf("got %v; want 42", got)
		}
	}))
	if n != 0 {
		t.Errorf("allocs = %v; want 0", n)
	}
}

func TestGMapMustSet(t *testing.T) {
	var gm GMap[string, int]
	gm.MustSet("42", 42)
	defer func() {
		if e := recover(); e == nil {
			t.Errorf("unexpected success; want panic")
		}
	}()
	gm.MustSet("42", 43)
}

func TestGMapRecursivePanic(t *testing.T) {
	defer func() {
		if e := recover(); e != nil {
			t.Logf("got panic, as expected")
		} else {
			t.Errorf("unexpected success; want panic")
		}
	}()
	gm := GMap[string, int]{}
	gm.Get("42", func() int {
		return gm.Get("42", func() int { return 42 })
	})
}

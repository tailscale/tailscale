// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"runtime"
	"sync"
	"testing"
)

func TestGuardCloseAndWait(t *testing.T) {
	t.Parallel()

	g := newGuard()
	g.Close()
	g.Wait()
}

func TestGuardAcquireReleaseCloseAndWait(t *testing.T) {
	t.Parallel()

	g := newGuard()
	if !g.Acquire() {
		t.Fatal("Acquire failed")
	}
	g.Release()
	g.Close()
	g.Wait()
}

func TestGuardAcquireCloseReleaseAndWait(t *testing.T) {
	t.Parallel()

	g := newGuard()
	if !g.Acquire() {
		t.Fatal("Acquire failed")
	}
	g.Close()
	if g.Acquire() {
		t.Fatal("Acquire succeeded after Close")
	}
	g.Release()
	if g.Acquire() {
		t.Fatal("Acquire succeeded after Release following Close")
	}
	g.Wait()
}

func TestGuardConcurrentUse(t *testing.T) {
	t.Parallel()

	const N = 1000
	g := newGuard()

	var wg sync.WaitGroup
	wg.Add(N)
	for range N {
		go func() {
			wg.Done()
			if !g.Acquire() {
				return
			}
			runtime.Gosched()
			g.Release()
		}()
	}
	wg.Wait() // wait for all goroutines to start

	g.Close()
	g.Wait()
}

func TestReleaseWithoutAcquire(t *testing.T) {
	t.Parallel()

	g := newGuard()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on Release without Acquire")
		}
	}()
	g.Release()
}

func TestReleaseWithoutAcquireAfterClose(t *testing.T) {
	t.Parallel()

	g := newGuard()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on Release without Acquire")
		}
	}()
	g.Close()
	g.Release()
}

func TestWaitBeforeClose(t *testing.T) {
	t.Parallel()

	g := newGuard()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on Wait before Close")
		}
	}()
	g.Wait()
}

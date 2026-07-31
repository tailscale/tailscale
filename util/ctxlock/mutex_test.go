// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ctxlock

import (
	"context"
	"fmt"
	"testing"
)

func BenchmarkReentrantMutex(b *testing.B) {
	b.ReportAllocs()
	// Does not allocate with --tags=ts_omit_ctxlock_checks.
	b.Run("ctxlock.State", func(b *testing.B) {
		var mu ReentrantMutex
		for b.Loop() {
			reentrantMutexLockUnlock(&mu, None)
		}
	})
	b.Run("context.Context", func(b *testing.B) {
		var mu ReentrantMutex
		for b.Loop() {
			reentrantMutexLockUnlock(&mu, context.Background)
		}
	})
}

func TestReentrantMutexAllocFree(t *testing.T) {
	if IsChecked {
		t.Skip("Exported implementation is not alloc-free (use --tags=ts_omit_ctxlock_checks).")
	}

	const N = 1000
	t.Run("ctxlock.State", func(t *testing.T) {
		var mu ReentrantMutex
		if allocs := testing.AllocsPerRun(N, func() {
			reentrantMutexLockUnlock(&mu, None)
		}); allocs != 0 {
			t.Errorf("expected 0 allocs, got %f", allocs)
		}
	})
	t.Run("context.Context", func(t *testing.T) {
		var mu ReentrantMutex
		if allocs := testing.AllocsPerRun(N, func() {
			reentrantMutexLockUnlock(&mu, context.Background)
		}); allocs != 0 {
			t.Errorf("expected 0 allocs, got %f", allocs)
		}
	})
}

func reentrantMutexLockUnlock[T context.Context](mu *ReentrantMutex, rootState func() T) {
	parent := Lock(rootState(), mu)
	func(state State) {
		child := Lock(state, mu)
		child.Unlock()
	}(parent.State())
	parent.Unlock()
}

func TestMutexRank(t *testing.T) {
	var m1 mutex1
	var m2 mutex2
	var m3 mutex3
	// Locking m1, m2, and m3 in order is valid.
	lock := Lock(None(), &m1)
	defer lock.Unlock()
	lock = Lock(lock.State(), &m2)
	defer lock.Unlock()
	lock = Lock(lock.State(), &m3)
	defer lock.Unlock()
}

func TestMutexLockOrderViolation(t *testing.T) {
	var m1 mutex1
	var m2 mutex2
	var m3 mutex3
	// Locking m2 m3, and then m1 is invalid.
	lock := Lock(None(), &m2)
	defer lock.Unlock()
	lock = Lock(lock.State(), &m3)
	defer lock.Unlock()
	wantPanic(t, "cannot lock ctxlock.testRank1 after ctxlock.testRank3", func() {
		lock := Lock(lock.State(), &m1)
		defer lock.Unlock()
	})
}

type (
	testRank1 struct{}
	testRank2 struct{}
	testRank3 struct{}

	mutex1 = Mutex[testRank1]
	mutex2 = Mutex[testRank2]
	mutex3 = Mutex[testRank3]
)

func (r testRank1) CheckLockAfter(r2 Rank) error {
	switch r2.(type) {
	case testRank2, testRank3:
		return fmt.Errorf("cannot lock %T after %T", r, r2)
	default:
		return nil
	}
}

func (r testRank2) CheckLockAfter(r2 Rank) error {
	switch r2.(type) {
	case testRank2, testRank3:
		return fmt.Errorf("cannot lock %T after %T", r, r2)
	default:
		return nil
	}
}

func (a testRank3) CheckLockAfter(b Rank) error {
	return nil
}

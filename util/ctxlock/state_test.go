// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ctxlock

import (
	"context"
	"sync"
	"testing"

	"tailscale.com/util/ctxkey"
)

type state interface {
	context.Context
	Unlock()
}

type impl[T state] struct {
	None        func() T
	FromContext func(context.Context) T
	Lock        func(T, *sync.Mutex) T
	LockCtx     func(context.Context, *sync.Mutex) T
}

var (
	exportedImpl = impl[State]{
		None:        None,
		FromContext: FromContext,
		Lock:        Lock[State],
		LockCtx:     Lock[context.Context],
	}
	checkedImpl = impl[*checked]{
		None:        func() *checked { return nil },
		FromContext: fromContextChecked,
		Lock:        lockChecked,
		LockCtx: func(ctx context.Context, mu *sync.Mutex) *checked {
			return lockChecked(fromContextChecked(ctx), mu)
		},
	}
	uncheckedImpl = impl[unchecked]{
		None:        func() unchecked { return unchecked{} },
		FromContext: fromContextUnchecked,
		Lock:        lockUnchecked,
		LockCtx: func(ctx context.Context, mu *sync.Mutex) unchecked {
			return lockUnchecked(fromContextUnchecked(ctx), mu)
		},
	}
)

// BenchmarkLockUnlock benchmarks the performance of locking and unlocking a mutex.
func BenchmarkLockUnlock(b *testing.B) {
	var mu sync.Mutex
	b.Run("Exported", func(b *testing.B) {
		benchmarkLockUnlock(b, exportedImpl)
	})
	b.Run("Checked", func(b *testing.B) {
		benchmarkLockUnlock(b, checkedImpl)
	})
	b.Run("Unchecked", func(b *testing.B) {
		benchmarkLockUnlock(b, uncheckedImpl)
	})
	b.Run("Reference", func(b *testing.B) {
		for b.Loop() {
			mu.Lock()
			mu.Unlock()
		}
	})
}

func benchmarkLockUnlock[T state](b *testing.B, impl impl[T]) {
	var mu sync.Mutex
	for b.Loop() {
		ctx := impl.Lock(impl.None(), &mu)
		ctx.Unlock()
	}
}

// BenchmarkReentrance benchmarks the performance of reentrant locking and unlocking.
func BenchmarkReentrance(b *testing.B) {
	var mu sync.Mutex

	b.Run("Exported", func(b *testing.B) {
		benchmarkReentrance(b, exportedImpl)
	})
	b.Run("Checked", func(b *testing.B) {
		benchmarkReentrance(b, checkedImpl)
	})
	b.Run("Unchecked", func(b *testing.B) {
		benchmarkReentrance(b, uncheckedImpl)
	})
	b.Run("Reference", func(b *testing.B) {
		for b.Loop() {
			mu.Lock()
			func(mu *sync.Mutex) {
				if mu.TryLock() {
					mu.Unlock()
				}
			}(&mu)
			mu.Unlock()
		}
	})
}

func benchmarkReentrance[T state](b *testing.B, impl impl[T]) {
	var mu sync.Mutex
	for b.Loop() {
		parent := impl.Lock(impl.None(), &mu)
		func(ctx T) {
			child := impl.Lock(ctx, &mu)
			child.Unlock()
		}(parent)
		parent.Unlock()
	}
}

// BenchmarkGenericLock benchmarks the performance of the generic [Lock] function
// that works with both [State] and [context.Context].
func BenchmarkGenericLock(b *testing.B) {
	// Does not allocate with --tags=ts_omit_ctxlock_checks.
	b.Run("State", func(b *testing.B) {
		var mu sync.Mutex
		var ctx State
		for b.Loop() {
			parent := Lock(ctx, &mu)
			func(ctx State) {
				child := Lock(ctx, &mu)
				child.Unlock()
			}(parent)
			parent.Unlock()
		}
	})
	b.Run("StdContext", func(b *testing.B) {
		var mu sync.Mutex
		ctx := context.Background()
		for b.Loop() {
			parent := Lock(ctx, &mu)
			func(ctx State) {
				child := Lock(ctx, &mu)
				child.Unlock()
			}(parent)
			parent.Unlock()
		}
	})
}

// TestUncheckedAllocFree tests that the exported implementation of [State] does not allocate memory
// when the ts_omit_ctxlock_checks build tag is set.
func TestUncheckedAllocFree(t *testing.T) {
	if Checked {
		t.Skip("Exported implementation is not alloc-free (use --tags=ts_omit_ctxlock_checks)")
	}
	t.Run("Simple/WithState", func(t *testing.T) {
		var mu sync.Mutex
		mustNotAllocate(t, func() {
			ctx := Lock(None(), &mu)
			ctx.Unlock()
		})
	})

	t.Run("Simple/WithContext", func(t *testing.T) {
		var mu sync.Mutex
		ctx := context.Background()
		mustNotAllocate(t, func() {
			ctx := Lock(ctx, &mu)
			ctx.Unlock()
		})
	})

	t.Run("Reentrant/WithState", func(t *testing.T) {
		var mu sync.Mutex
		mustNotAllocate(t, func() {
			parent := Lock(None(), &mu)
			func(ctx State) {
				child := Lock(parent, &mu)
				child.Unlock()
			}(parent)
			parent.Unlock()
		})
	})

	t.Run("Reentrant/WithContext", func(t *testing.T) {
		var mu sync.Mutex
		ctx := context.Background()
		mustNotAllocate(t, func() {
			parent := Lock(ctx, &mu)
			func(ctx State) {
				child := Lock(ctx, &mu)
				child.Unlock()
			}(parent)
			parent.Unlock()
		})
	})
}

func TestHappyPath(t *testing.T) {
	t.Run("Exported", func(t *testing.T) {
		testHappyPath(t, exportedImpl)
	})

	t.Run("Checked", func(t *testing.T) {
		testHappyPath(t, checkedImpl)
	})

	t.Run("Unchecked", func(t *testing.T) {
		testHappyPath(t, uncheckedImpl)
	})
}

func testHappyPath[T state](t *testing.T, impl impl[T]) {
	var mu sync.Mutex
	parent := impl.Lock(impl.None(), &mu)
	wantLocked(t, &mu) // mu is locked by parent

	child := impl.Lock(parent, &mu)
	wantLocked(t, &mu) // mu is still locked by parent

	var mu2 sync.Mutex
	ls2 := impl.Lock(child, &mu2)
	wantLocked(t, &mu2)   // mu2 is locked by ls2
	ls2.Unlock()          // unlocks mu2
	wantUnlocked(t, &mu2) // mu2 is now unlocked

	child.Unlock()     // noop
	wantLocked(t, &mu) // mu is still locked by parent

	parent.Unlock()      // unlocks mu
	wantUnlocked(t, &mu) // mu is now unlocked
}

func TestContextWrapping(t *testing.T) {
	t.Run("Exported", func(t *testing.T) {
		testContextWrapping(t, exportedImpl)
	})

	t.Run("Checked", func(t *testing.T) {
		testContextWrapping(t, checkedImpl)
	})

	t.Run("Unchecked", func(t *testing.T) {
		testContextWrapping(t, uncheckedImpl)
	})
}

func testContextWrapping[T state](t *testing.T, impl impl[T]) {
	// Create a [context.Context] with a value set in it.
	wantValue := "value"
	key := ctxkey.New("key", "")
	ctxWithValue := key.WithValue(context.Background(), wantValue)

	var mu sync.Mutex
	parent := impl.LockCtx(ctxWithValue, &mu)
	wantLocked(t, &mu) // mu is locked by parent

	// Let's assume that we want to call a function that takes a [context.Context].
	// [State] is a valid [context.Context], so we can pass it to the function.
	ctx := context.Context(parent)
	// If / when necessary, we can convert it back to a [State].
	// The [State] should carry the same lock state as the parent context.
	parentDup := impl.FromContext(ctx)

	// We can then create and use a child [State].
	child := impl.Lock(parentDup, &mu)

	// It still carries all the original context values...
	if gotValue := key.Value(child); gotValue != wantValue {
		t.Errorf("key.Value() = %s; want %s", gotValue, wantValue)
	}

	// ... and the lock state.
	child.Unlock()     // no-op; mu is owned by parent
	wantLocked(t, &mu) // mu is still locked by parent

	parentDup.Unlock() // no-op; mu is owned by parent
	wantLocked(t, &mu) // mu is still locked by parent

	parent.Unlock()      // unlocks mu
	wantUnlocked(t, &mu) // mu is now unlocked
}

func TestNilMutex(t *testing.T) {
	impl := checkedImpl
	wantPanic(t, "nil *sync.Mutex", func() { impl.Lock(impl.None(), nil) })
}

func TestUseUnlockedParent_Checked(t *testing.T) {
	impl := checkedImpl

	var mu sync.Mutex
	parent := impl.Lock(impl.None(), &mu)
	parent.Unlock()      // unlocks mu
	wantUnlocked(t, &mu) // mu is now unlocked
	wantPanic(t, "use after unlock", func() { impl.Lock(parent, &mu) })
}

func TestUseUnlockedMutex_Checked(t *testing.T) {
	impl := checkedImpl

	var mu sync.Mutex
	parent := impl.Lock(impl.None(), &mu)
	mu.Unlock() // unlock mu directly without unlocking parent
	wantPanic(t, "*sync.Mutex is spuriously unlocked", func() { impl.Lock(parent, &mu) })
}

func TestUnlockParentFirst_Checked(t *testing.T) {
	impl := checkedImpl

	var mu sync.Mutex
	parent := impl.Lock(impl.FromContext(context.Background()), &mu)
	child := impl.Lock(parent, &mu)

	parent.Unlock()      // unlocks mu
	wantUnlocked(t, &mu) // mu is now unlocked
	wantPanic(t, "parent already unlocked", child.Unlock)
}

func TestUnlockTwice_Checked(t *testing.T) {
	impl := checkedImpl

	unlockTwice := func(t *testing.T, ctx *checked) {
		ctx.Unlock() // unlocks mu
		wantPanic(t, "already unlocked", ctx.Unlock)
	}

	t.Run("Wrapped", func(t *testing.T) {
		unlockTwice(t, impl.FromContext(context.Background()))
	})
	t.Run("Locked", func(t *testing.T) {
		var mu sync.Mutex
		ctx := impl.Lock(impl.None(), &mu)
		unlockTwice(t, ctx)
	})
	t.Run("Locked/WithReloc", func(t *testing.T) {
		var mu sync.Mutex
		ctx := impl.Lock(impl.None(), &mu)
		ctx.Unlock() // unlocks mu
		mu.Lock()    // re-locks mu, but not by the state
		wantPanic(t, "already unlocked", ctx.Unlock)
	})
	t.Run("Child", func(t *testing.T) {
		var mu sync.Mutex
		parent := impl.Lock(impl.None(), &mu)
		defer parent.Unlock()
		child := impl.Lock(parent, &mu)
		unlockTwice(t, child)
	})
	t.Run("Child/WithReloc", func(t *testing.T) {
		var mu sync.Mutex
		parent := impl.Lock(impl.None(), &mu)
		child := impl.Lock(parent, &mu)
		parent.Unlock()
		mu.Lock() // re-locks mu, but not the parent state
		wantPanic(t, "parent already unlocked", child.Unlock)
	})
	t.Run("Child/WithManualUnlock", func(t *testing.T) {
		var mu sync.Mutex
		parent := impl.Lock(impl.None(), &mu)
		child := impl.Lock(parent, &mu)
		mu.Unlock() // unlocks mu, but not the parent state
		wantPanic(t, "mutex is not locked", child.Unlock)
	})
	t.Run("Grandchild", func(t *testing.T) {
		var mu sync.Mutex
		parent := impl.Lock(impl.None(), &mu)
		defer parent.Unlock()
		child := impl.Lock(parent, &mu)
		defer child.Unlock()
		grandchild := impl.Lock(child, &mu)
		unlockTwice(t, grandchild)
	})
}

func TestUseUnlocked_Checked(t *testing.T) {
	impl := checkedImpl

	var mu sync.Mutex
	state := lockChecked(impl.None(), &mu)
	state.Unlock()

	// All of these should panic since the state is already unlocked.
	wantPanic(t, "", func() { state.Deadline() })
	wantPanic(t, "", func() { state.Done() })
	wantPanic(t, "", func() { state.Err() })
	wantPanic(t, "", func() { state.Unlock() })
	wantPanic(t, "", func() { state.Value("key") })
}

func TestUseZeroState(t *testing.T) {
	t.Run("Exported", func(t *testing.T) {
		testUseEmptyState(t, exportedImpl.None, exportedImpl)
	})
	t.Run("Checked", func(t *testing.T) {
		testUseEmptyState(t, checkedImpl.None, checkedImpl)
	})
	t.Run("Unchecked", func(t *testing.T) {
		testUseEmptyState(t, uncheckedImpl.None, uncheckedImpl)
	})
}

func TestUseWrappedBackground(t *testing.T) {
	t.Run("Exported", func(t *testing.T) {
		testUseEmptyState(t, getWrappedBackground(t, exportedImpl), exportedImpl)
	})
	t.Run("Checked", func(t *testing.T) {
		testUseEmptyState(t, getWrappedBackground(t, checkedImpl), checkedImpl)
	})
	t.Run("Unchecked", func(t *testing.T) {
		testUseEmptyState(t, getWrappedBackground(t, uncheckedImpl), uncheckedImpl)
	})
}

func getWrappedBackground[T state](t *testing.T, impl impl[T]) func() T {
	t.Helper()
	return func() T {
		return impl.FromContext(context.Background())
	}
}

func testUseEmptyState[T state](t *testing.T, getCtx func() T, impl impl[T]) {
	// Using aan empty [State] must not panic or deadlock.
	// It should also behave like [context.Background].
	for range 2 {
		ctx := getCtx()
		if gotDone := ctx.Done(); gotDone != nil {
			t.Errorf("ctx.Done() = %v; want nil", gotDone)
		}
		if gotDeadline, ok := ctx.Deadline(); ok {
			t.Errorf("ctx.Deadline() = %v; want !ok", gotDeadline)
		}
		if gotErr := ctx.Err(); gotErr != nil {
			t.Errorf("ctx.Err() = %v; want nil", gotErr)
		}
		if gotValue := ctx.Value("test-key"); gotValue != nil {
			t.Errorf("ctx.Value(test-key) = %v; want nil", gotValue)
		}
		ctx.Unlock()
	}
}

func wantPanic(t *testing.T, wantMsg string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); wantMsg != "" {
			if gotMsg, ok := r.(string); !ok || gotMsg != wantMsg {
				t.Errorf("panic: %v; want %q", r, wantMsg)
			}
		}
	}()
	fn()
	t.Fatal("failed to panic")
}

func wantLocked(t *testing.T, m *sync.Mutex) {
	if m.TryLock() {
		m.Unlock()
		t.Fatal("mutex is not locked")
	}
}

func wantUnlocked(t *testing.T, m *sync.Mutex) {
	t.Helper()
	if !m.TryLock() {
		t.Fatal("mutex is locked")
	}
	m.Unlock()
}

func mustNotAllocate(t *testing.T, steps func()) {
	t.Helper()
	const runs = 1000
	if allocs := testing.AllocsPerRun(runs, steps); allocs != 0 {
		t.Errorf("expected 0 allocs, got %f", allocs)
	}
}

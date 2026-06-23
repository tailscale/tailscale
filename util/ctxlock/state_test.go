// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ctxlock

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"tailscale.com/util/ctxkey"
)

type stateType interface {
	*checked | unchecked
	context.Context
	unlock()
}

type lockStateType interface{ lockCallers | unchecked }

type impl[T stateType, S lockStateType] struct {
	None        func() T
	FromContext func(context.Context) T
	Lock        func(T, *mutex[Reentrant, S]) T
	LockCtx     func(context.Context, *mutex[Reentrant, S]) T
}

var (
	checkedImpl = impl[*checked, lockCallers]{
		None:        func() *checked { return nil },
		FromContext: fromContextChecked,
		Lock:        lockChecked[Reentrant],
		LockCtx: func(ctx context.Context, mu *checkedMutex[Reentrant]) *checked {
			return lockChecked(fromContextChecked(ctx), mu)
		},
	}
	uncheckedImpl = impl[unchecked, unchecked]{
		None:        func() unchecked { return unchecked{} },
		FromContext: fromContextUnchecked,
		Lock:        lockUnchecked[Reentrant],
		LockCtx: func(ctx context.Context, mu *mutex[Reentrant, unchecked]) unchecked {
			return lockUnchecked(fromContextUnchecked(ctx), mu)
		},
	}
)

// BenchmarkStateLockUnlock benchmarks the performance of locking and unlocking a mutex.
func BenchmarkStateLockUnlock(b *testing.B) {
	b.Run("Checked", func(b *testing.B) {
		benchmarkStateLockUnlock(b, checkedImpl)
	})
	b.Run("Unchecked", func(b *testing.B) {
		benchmarkStateLockUnlock(b, uncheckedImpl)
	})
	b.Run("Reference", func(b *testing.B) {
		var mu sync.Mutex
		for b.Loop() {
			mu.Lock()
			mu.Unlock()
		}
	})
}

func benchmarkStateLockUnlock[T stateType, S lockStateType](b *testing.B, impl impl[T, S]) {
	var mu mutex[Reentrant, S]
	for b.Loop() {
		state := impl.Lock(impl.None(), &mu)
		state.unlock()
	}
}

// BenchmarkReentrance benchmarks the performance of reentrant locking and unlocking.
func BenchmarkReentrance(b *testing.B) {
	b.Run("Checked", func(b *testing.B) {
		benchmarkReentrance(b, checkedImpl)
	})
	b.Run("Unchecked", func(b *testing.B) {
		benchmarkReentrance(b, uncheckedImpl)
	})
	b.Run("Reference", func(b *testing.B) {
		var mu sync.Mutex
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

func benchmarkReentrance[T stateType, S lockStateType](b *testing.B, impl impl[T, S]) {
	var mu mutex[Reentrant, S]
	for b.Loop() {
		parent := impl.Lock(impl.None(), &mu)
		func(ctx T) {
			child := impl.Lock(ctx, &mu)
			child.unlock()
		}(parent)
		parent.unlock()
	}
}

// TestUncheckedAllocFree tests that the exported implementation of [State] does not allocate memory
// when the ts_omit_ctxlock_checks build tag is set.
func TestUncheckedAllocFree(t *testing.T) {
	if IsChecked {
		t.Skip("Exported implementation is not alloc-free (use --tags=ts_omit_ctxlock_checks)")
	}
	t.Run("Simple/WithState", func(t *testing.T) {
		var mu ReentrantMutex
		mustNotAllocate(t, func() {
			mu := Lock(None(), &mu)
			mu.Unlock()
		})
	})

	t.Run("Simple/WithContext", func(t *testing.T) {
		var mu ReentrantMutex
		ctx := context.Background()
		mustNotAllocate(t, func() {
			mu := Lock(ctx, &mu)
			mu.Unlock()
		})
	})

	t.Run("Reentrant/WithState", func(t *testing.T) {
		var mu ReentrantMutex
		mustNotAllocate(t, func() {
			parent := Lock(None(), &mu)
			func(state State) {
				child := Lock(state, &mu)
				child.Unlock()
			}(parent.State())
			parent.Unlock()
		})
	})

	t.Run("Reentrant/WithContext", func(t *testing.T) {
		var mu ReentrantMutex
		ctx := context.Background()
		mustNotAllocate(t, func() {
			parent := Lock(ctx, &mu)
			func(state State) {
				child := Lock(state, &mu)
				child.Unlock()
			}(parent.State())
			parent.Unlock()
		})
	})
}

func TestHappyPath(t *testing.T) {
	t.Run("Checked", func(t *testing.T) {
		testHappyPath(t, checkedImpl)
	})

	t.Run("Unchecked", func(t *testing.T) {
		testHappyPath(t, uncheckedImpl)
	})
}

func testHappyPath[T stateType, S lockStateType](t *testing.T, impl impl[T, S]) {
	var mu mutex[Reentrant, S]
	parent := impl.Lock(impl.None(), &mu)
	wantLocked(t, &mu) // mu is locked by parent

	child := impl.Lock(parent, &mu)
	wantLocked(t, &mu) // mu is still locked by parent

	var mu2 mutex[Reentrant, S]
	ls2 := impl.Lock(child, &mu2)
	wantLocked(t, &mu2) // mu2 is locked by ls2

	grandchild := impl.Lock(ls2, &mu)
	grandchild.unlock() // no-op; mu is owned by parent
	wantLocked(t, &mu)  // mu is still locked by parent

	ls2.unlock()          // unlocks mu2
	wantUnlocked(t, &mu2) // mu2 is now unlocked

	child.unlock()     // noop
	wantLocked(t, &mu) // mu is still locked by parent

	parent.unlock()      // unlocks mu
	wantUnlocked(t, &mu) // mu is now unlocked
}

func TestContextWrapping(t *testing.T) {
	t.Run("Checked", func(t *testing.T) {
		testContextWrapping(t, checkedImpl)
	})

	t.Run("Unchecked", func(t *testing.T) {
		testContextWrapping(t, uncheckedImpl)
	})
}

func testContextWrapping[T stateType, S lockStateType](t *testing.T, impl impl[T, S]) {
	// Create a [context.Context] with a value set in it.
	wantValue := "value"
	key := ctxkey.New("key", "")
	ctxWithValue := key.WithValue(context.Background(), wantValue)

	var mu mutex[Reentrant, S]
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
	child.unlock()     // no-op; mu is owned by parent
	wantLocked(t, &mu) // mu is still locked by parent

	parentDup.unlock() // no-op; mu is owned by parent
	wantLocked(t, &mu) // mu is still locked by parent

	parent.unlock()      // unlocks mu
	wantUnlocked(t, &mu) // mu is now unlocked
}

func TestNilMutex(t *testing.T) {
	impl := checkedImpl
	wantPanic(t, "nil mutex", func() { impl.Lock(impl.None(), nil) })
}

func TestUseUnlockedParent_Checked(t *testing.T) {
	impl := checkedImpl

	var mu checkedMutex[Reentrant]
	parent := impl.Lock(impl.None(), &mu)
	parent.unlock()      // unlocks mu
	wantUnlocked(t, &mu) // mu is now unlocked
	wantPanic(t, "use after unlock", func() { impl.Lock(parent, &mu) })
}

func TestUnlockParentFirst_Checked(t *testing.T) {
	impl := checkedImpl

	var mu checkedMutex[Reentrant]
	parent := impl.Lock(impl.FromContext(context.Background()), &mu)
	child := impl.Lock(parent, &mu)

	parent.unlock()      // unlocks mu
	wantUnlocked(t, &mu) // mu is now unlocked
	wantPanic(t, "parent already unlocked", child.unlock)
}

func TestUnlockTwice_Checked(t *testing.T) {
	impl := checkedImpl

	unlockTwice := func(t *testing.T, ctx *checked) {
		ctx.unlock() // unlocks mu
		wantPanic(t, "already unlocked", ctx.unlock)
	}

	t.Run("Wrapped", func(t *testing.T) {
		unlockTwice(t, impl.FromContext(context.Background()))
	})
	t.Run("Locked", func(t *testing.T) {
		var mu checkedMutex[Reentrant]
		ctx := impl.Lock(impl.None(), &mu)
		unlockTwice(t, ctx)
	})
	t.Run("Child", func(t *testing.T) {
		var mu checkedMutex[Reentrant]
		parent := impl.Lock(impl.None(), &mu)
		defer parent.unlock()
		child := impl.Lock(parent, &mu)
		unlockTwice(t, child)
	})
	t.Run("Grandchild", func(t *testing.T) {
		var mu checkedMutex[Reentrant]
		parent := impl.Lock(impl.None(), &mu)
		defer parent.unlock()
		child := impl.Lock(parent, &mu)
		defer child.unlock()
		grandchild := impl.Lock(child, &mu)
		unlockTwice(t, grandchild)
	})
}

func TestUseUnlocked_Checked(t *testing.T) {
	impl := checkedImpl

	var mu checkedMutex[Reentrant]
	state := lockChecked(impl.None(), &mu)
	state.unlock()

	// All of these should panic since the state is already unlocked.
	wantPanic(t, "*", func() { state.Deadline() })
	wantPanic(t, "*", func() { state.Done() })
	wantPanic(t, "*", func() { state.Err() })
	wantPanic(t, "*", func() { state.unlock() })
	wantPanic(t, "*", func() { state.Value("key") })
}

func TestUseZeroState(t *testing.T) {
	t.Run("Checked", func(t *testing.T) {
		testUseEmptyState(t, checkedImpl.None)
	})
	t.Run("Unchecked", func(t *testing.T) {
		testUseEmptyState(t, uncheckedImpl.None)
	})
}

func TestUseWrappedBackground(t *testing.T) {
	t.Run("Checked", func(t *testing.T) {
		testUseEmptyState(t, getWrappedBackground(t, checkedImpl))
	})
	t.Run("Unchecked", func(t *testing.T) {
		testUseEmptyState(t, getWrappedBackground(t, uncheckedImpl))
	})
}

func getWrappedBackground[T stateType, S lockStateType](t *testing.T, impl impl[T, S]) func() T {
	t.Helper()
	return func() T {
		return impl.FromContext(context.Background())
	}
}

func testUseEmptyState[T stateType](t *testing.T, getState func() T) {
	// Using an empty [State] must not panic or deadlock.
	// It should also behave like [context.Background].
	for range 2 {
		state := getState()
		if gotDone := state.Done(); gotDone != nil {
			t.Errorf("ctx.Done() = %v; want nil", gotDone)
		}
		if gotDeadline, ok := state.Deadline(); ok {
			t.Errorf("ctx.Deadline() = %v; want !ok", gotDeadline)
		}
		if gotErr := state.Err(); gotErr != nil {
			t.Errorf("ctx.Err() = %v; want nil", gotErr)
		}
		if gotValue := state.Value("test-key"); gotValue != nil {
			t.Errorf("ctx.Value(test-key) = %v; want nil", gotValue)
		}
		state.unlock()
	}
}

func wantPanic(t *testing.T, wantMsg string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); wantMsg != "*" {
			if gotMsg := trimPanicMessage(r); gotMsg != wantMsg {
				t.Errorf("panic: got %q; want %q", r, wantMsg)
			}
		}
	}()
	fn()
	t.Fatal("failed to panic")
}

func (m *mutex[R, S]) isLockedForTest() bool {
	if m.m.TryLock() {
		m.m.Unlock()
		return false
	}
	return true
}

func wantLocked[R Rank, S lockStateType](t *testing.T, m *mutex[R, S]) {
	t.Helper()
	if !m.isLockedForTest() {
		t.Fatal("mutex is not locked")
	}
}

func wantUnlocked[R Rank, S lockStateType](t *testing.T, m *mutex[R, S]) {
	t.Helper()
	if m.isLockedForTest() {
		t.Fatal("mutex is locked")
	}
}

func mustNotAllocate(t *testing.T, steps func()) {
	t.Helper()
	const runs = 1000
	if allocs := testing.AllocsPerRun(runs, steps); allocs != 0 {
		t.Errorf("expected 0 allocs, got %f", allocs)
	}
}

func trimPanicMessage(r any) string {
	msg := fmt.Sprintf("%v", r)
	msg = strings.TrimSpace(msg)
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		return msg[:i]
	}
	return msg
}

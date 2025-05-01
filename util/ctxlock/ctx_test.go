// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ctxlock

import (
	"context"
	"sync"
	"testing"

	"tailscale.com/util/ctxkey"
)

type ctx interface {
	context.Context
	Unlock()
}

type impl[T ctx] struct {
	None func() T
	Wrap func(context.Context) T
	Lock func(T, *sync.Mutex) T
}

var (
	exportedImpl = impl[Context[*sync.Mutex]]{
		None: None[*sync.Mutex],
		Wrap: Wrap[*sync.Mutex],
		Lock: Lock[*sync.Mutex, *sync.Mutex],
	}
	checkedImpl = impl[*checked[*sync.Mutex]]{
		None: noneChecked[*sync.Mutex],
		Wrap: wrapChecked[*sync.Mutex],
		Lock: lockChecked[*sync.Mutex, *sync.Mutex],
	}
	uncheckedImpl = impl[unchecked[*sync.Mutex]]{
		None: noneUnchecked[*sync.Mutex],
		Wrap: wrapUnchecked[*sync.Mutex],
		Lock: lockUnchecked[*sync.Mutex, *sync.Mutex],
	}
)

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
		for i := 0; i < b.N; i++ {
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

func benchmarkReentrance[T ctx](b *testing.B, impl impl[T]) {
	var mu sync.Mutex
	for i := 0; i < b.N; i++ {
		parent := impl.Lock(impl.None(), &mu)
		func(ctx T) {
			child := impl.Lock(ctx, &mu)
			child.Unlock()
		}(parent)
		parent.Unlock()
	}
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

func testHappyPath[T ctx](t *testing.T, impl impl[T]) {
	var mu sync.Mutex
	parent := impl.Lock(impl.None(), &mu)
	wantLocked(t, &mu) // mu is locked by parent

	child := impl.Lock(parent, &mu)
	wantLocked(t, &mu) // mu is still locked by parent

	var mu2 sync.Mutex
	context2 := impl.Lock(child, &mu2)
	wantLocked(t, &mu2)   // mu2 is locked by context2
	context2.Unlock()     // unlocks mu2
	wantUnlocked(t, &mu2) // mu2 is now unlocked

	child.Unlock()     // noop
	wantLocked(t, &mu) // mu is still locked by parent

	parent.Unlock()      // unlocks mu
	wantUnlocked(t, &mu) // mu is now unlocked
}

func TestWrappedLockContext(t *testing.T) {
	t.Run("Exported", func(t *testing.T) {
		testWrappedLockContext(t, exportedImpl)
	})

	t.Run("Checked", func(t *testing.T) {
		testWrappedLockContext(t, checkedImpl)
	})

	t.Run("Unchecked", func(t *testing.T) {
		testWrappedLockContext(t, uncheckedImpl)
	})
}

func testWrappedLockContext[T ctx](t *testing.T, impl impl[T]) {
	wantValue := "value"
	key := ctxkey.New("key", "")
	ctxWithValue := key.WithValue(context.Background(), wantValue)
	root := impl.Wrap(ctxWithValue)

	var mu sync.Mutex
	parent := impl.Lock(root, &mu)
	wantLocked(t, &mu) // mu is locked by parent

	// Wrap the parent context as if it were a regular [context.Context],
	// then create a child context from it.
	// The child should still recognize the parent as the mutex owner,
	// and not panic or deadlock attempting to lock it again.
	wrapped := impl.Wrap(parent)
	child := impl.Lock(wrapped, &mu)

	// We should be able to access the value set in the root context.
	if gotValue := key.Value(child); gotValue != wantValue {
		t.Errorf("key.Value() = %s; want %s", gotValue, wantValue)
	}

	child.Unlock()     // no-op; mu is owned by parent
	wantLocked(t, &mu) // mu is still locked by parent

	wrapped.Unlock()   // no-op; mu is owned by parent
	wantLocked(t, &mu) // mu is still locked by parent

	parent.Unlock()      // unlocks mu
	wantUnlocked(t, &mu) // mu is now unlocked
}

func TestNilContextAndMutex(t *testing.T) {
	t.Run("Exported", func(t *testing.T) {
		testNilContextAndMutex(t, exportedImpl)
	})

	t.Run("Checked", func(t *testing.T) {
		testNilContextAndMutex(t, checkedImpl)
	})

	t.Run("Unchecked", func(t *testing.T) {
		testNilContextAndMutex(t, uncheckedImpl)
	})
}

func testNilContextAndMutex[T ctx](t *testing.T, impl impl[T]) {
	t.Run("NilContext", func(t *testing.T) {
		var zero T
		wantPanic(t, func() { impl.Lock(zero, &sync.Mutex{}) }) // panics since context is nil
	})
	t.Run("NilMutex", func(t *testing.T) {
		wantPanic(t, func() { impl.Lock(impl.None(), nil) }) // panics since mutex is nil
	})
}

func TestUseUnlockedParent_Checked(t *testing.T) {
	impl := checkedImpl

	var mu sync.Mutex
	parent := impl.Lock(impl.None(), &mu)
	parent.Unlock()                                 // unlocks mu
	wantUnlocked(t, &mu)                            // mu is now unlocked
	wantPanic(t, func() { impl.Lock(parent, &mu) }) // panics since parent is already unlocked
}

func TestUnlockParentFirst_Checked(t *testing.T) {
	impl := checkedImpl

	var mu sync.Mutex
	parent := impl.Lock(impl.None(), &mu)
	child := impl.Lock(parent, &mu)

	parent.Unlock()            // unlocks mu
	wantUnlocked(t, &mu)       // mu is now unlocked
	wantPanic(t, child.Unlock) // panics since mu is already unlocked by parent
}

func TestUnlockTwice_Checked(t *testing.T) {
	impl := checkedImpl

	doTest := func(t *testing.T, ctx *checked[*sync.Mutex]) {
		ctx.Unlock()             // unlocks mu
		wantPanic(t, ctx.Unlock) // panics since mu is already unlocked
	}

	t.Run("None", func(t *testing.T) {
		doTest(t, impl.None())
	})
	t.Run("Wrapped", func(t *testing.T) {
		doTest(t, impl.Wrap(context.Background()))
	})
	t.Run("Locked", func(t *testing.T) {
		var mu sync.Mutex
		ctx := impl.Lock(impl.None(), &mu)
		doTest(t, ctx)
	})
	t.Run("Locked/WithReloc", func(t *testing.T) {
		var mu sync.Mutex
		ctx := impl.Lock(impl.None(), &mu)
		ctx.Unlock() // unlocks mu
		mu.Lock()    // re-locks mu, but not by the context
		wantPanic(t, ctx.Unlock)
	})
	t.Run("Child", func(t *testing.T) {
		var mu sync.Mutex
		parent := impl.Lock(impl.None(), &mu)
		defer parent.Unlock()
		child := impl.Lock(parent, &mu)
		doTest(t, child)
	})
	t.Run("Child/WithReloc", func(t *testing.T) {
		var mu sync.Mutex
		parent := impl.Lock(impl.None(), &mu)
		child := impl.Lock(parent, &mu)
		parent.Unlock()
		mu.Lock() // re-locks mu, but not the parent context
		wantPanic(t, child.Unlock)
	})
	t.Run("Grandchild", func(t *testing.T) {
		var mu sync.Mutex
		parent := impl.Lock(impl.None(), &mu)
		defer parent.Unlock()
		child := impl.Lock(parent, &mu)
		defer child.Unlock()
		grandchild := impl.Lock(child, &mu)
		doTest(t, grandchild)
	})
}

func TestUseUnlocked_Checked(t *testing.T) {
	impl := checkedImpl

	var mu sync.Mutex
	ctx := lockChecked(impl.None(), &mu)
	ctx.Unlock()

	// All of these should panic since the context is already unlocked.
	wantPanic(t, func() { ctx.Deadline() })
	wantPanic(t, func() { ctx.Done() })
	wantPanic(t, func() { ctx.Err() })
	wantPanic(t, func() { ctx.Unlock() })
	wantPanic(t, func() { ctx.Value("key") })
}

func TestUseNoneContext(t *testing.T) {
	t.Run("Exported", func(t *testing.T) {
		testUseEmptyContext(t, exportedImpl.None, exportedImpl)
	})
	t.Run("Checked", func(t *testing.T) {
		testUseEmptyContext(t, checkedImpl.None, checkedImpl)
	})
	t.Run("Unchecked", func(t *testing.T) {
		testUseEmptyContext(t, uncheckedImpl.None, uncheckedImpl)
	})
}

func TestUseWrappedBackground(t *testing.T) {
	t.Run("Exported", func(t *testing.T) {
		testUseEmptyContext(t, getWrappedBackground(t, exportedImpl), exportedImpl)
	})
	t.Run("Checked", func(t *testing.T) {
		testUseEmptyContext(t, getWrappedBackground(t, checkedImpl), checkedImpl)
	})
	t.Run("Unchecked", func(t *testing.T) {
		testUseEmptyContext(t, getWrappedBackground(t, uncheckedImpl), uncheckedImpl)
	})
}

func getWrappedBackground[T ctx](t *testing.T, impl impl[T]) func() T {
	t.Helper()
	return func() T {
		return impl.Wrap(context.Background())
	}
}

func testUseEmptyContext[T ctx](t *testing.T, getCtx func() T, impl impl[T]) {
	// Using a None context must not panic or deadlock.
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

func wantPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		recover()
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

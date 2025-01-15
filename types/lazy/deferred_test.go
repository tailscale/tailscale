// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lazy

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func ExampleDeferredInit() {
	// DeferredInit allows both registration and invocation of the
	// deferred funcs. It should remain internal to the code that "owns" it.
	var di DeferredInit
	// Deferred funcs will not be executed until [DeferredInit.Do] is called.
	deferred := di.Defer(func() error {
		fmt.Println("Internal init")
		return nil
	})
	// [DeferredInit.Defer] reports whether the function was successfully deferred.
	// A func can only fail to defer if [DeferredInit.Do] has already been called.
	if deferred {
		fmt.Printf("Internal init has been deferred\n\n")
	}

	// If necessary, the value returned by [DeferredInit.Funcs]
	// can be shared with external code to facilitate deferring
	// funcs without allowing it to call [DeferredInit.Do].
	df := di.Funcs()
	// If a certain init step must be completed for the program
	// to function correctly, and failure to defer it indicates
	// a coding error, use [DeferredFuncs.MustDefer] instead of
	// [DeferredFuncs.Defer]. It panics if Do() has already been called.
	df.MustDefer(func() error {
		fmt.Println("External init - 1")
		return nil
	})
	// A deferred func may return an error to indicate a failed init.
	// If a deferred func returns an error, execution stops
	// and the error is propagated to the caller.
	df.Defer(func() error {
		fmt.Println("External init - 2")
		return errors.New("bang!")
	})
	// The deferred function below won't be executed.
	df.Defer(func() error {
		fmt.Println("Unreachable")
		return nil
	})

	// When [DeferredInit]'s owner needs initialization to be completed,
	// it can call [DeferredInit.Do]. When called for the first time,
	// it invokes the deferred funcs.
	err := di.Do()
	if err != nil {
		fmt.Printf("Deferred init failed: %v\n", err)
	}
	// [DeferredInit.Do] is safe for concurrent use and can be called
	// multiple times by the same or different goroutines.
	// However, the deferred functions are never invoked more than once.
	// If the deferred init fails on the first attempt, all subsequent
	// [DeferredInit.Do] calls will return the same error.
	if err = di.Do(); err != nil {
		fmt.Printf("Deferred init failed: %v\n\n", err)
	}

	// Additionally, all subsequent attempts to defer a function will fail
	// after [DeferredInit.Do] has been called.
	deferred = di.Defer(func() error {
		fmt.Println("Unreachable")
		return nil
	})
	if !deferred {
		fmt.Println("Cannot defer a func once init has been completed")
	}

	// Output:
	// Internal init has been deferred
	//
	// Internal init
	// External init - 1
	// External init - 2
	// Deferred init failed: bang!
	// Deferred init failed: bang!
	//
	// Cannot defer a func once init has been completed
}

func TestDeferredInit(t *testing.T) {
	tests := []struct {
		name     string
		numFuncs int
	}{
		{
			name:     "no-funcs",
			numFuncs: 0,
		},
		{
			name:     "one-func",
			numFuncs: 1,
		},
		{
			name:     "many-funcs",
			numFuncs: 1000,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var di DeferredInit

			calls := make([]atomic.Bool, tt.numFuncs) // whether N-th func has been called
			checkCalls := func() {
				t.Helper()
				for i := range calls {
					if !calls[i].Load() {
						t.Errorf("Func #%d has never been called", i)
					}
				}
			}

			// Defer funcs concurrently across multiple goroutines.
			var wg sync.WaitGroup
			wg.Add(tt.numFuncs)
			for i := range tt.numFuncs {
				go func() {
					f := func() error {
						if calls[i].Swap(true) {
							t.Errorf("Func #%d has already been called", i)
						}
						return nil
					}
					if !di.Defer(f) {
						t.Errorf("Func #%d cannot be deferred", i)
						return
					}
					wg.Done()
				}()
			}
			// Wait for all funcs to be deferred.
			wg.Wait()

			// Call [DeferredInit.Do] concurrently.
			const N = 10000
			for range N {
				wg.Add(1)
				go func() {
					gotErr := di.Do()
					checkError(t, gotErr, nil, false)
					checkCalls()
					wg.Done()
				}()
			}
			wg.Wait()
		})
	}
}

func TestDeferredErr(t *testing.T) {
	tests := []struct {
		name    string
		funcs   []func() error
		wantErr error
	}{
		{
			name:    "no-funcs",
			wantErr: nil,
		},
		{
			name:    "no-error",
			funcs:   []func() error{func() error { return nil }},
			wantErr: nil,
		},
		{
			name: "error",
			funcs: []func() error{
				func() error { return nil },
				func() error { return errors.New("bang!") },
				func() error { return errors.New("unreachable") },
			},
			wantErr: errors.New("bang!"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var di DeferredInit
			for _, f := range tt.funcs {
				di.MustDefer(f)
			}

			var wg sync.WaitGroup
			N := 10000
			for range N {
				wg.Add(1)
				go func() {
					gotErr := di.Do()
					checkError(t, gotErr, tt.wantErr, false)
					wg.Done()
				}()
			}
			wg.Wait()
		})
	}
}

// TestDeferAfterDo checks all of the following:
// - Deferring a function before [DeferredInit.Do] is called should always succeed.
// - All successfully deferred functions are executed by the time [DeferredInit.Do] completes.
// - No functions can be deferred after [DeferredInit.Do] is called, meaning:
//   - [DeferredInit.Defer] should return false.
//   - The deferred function should not be executed.
//
// This test is intentionally racy as it attempts to defer functions from multiple goroutines
// and then calls [DeferredInit.Do] without waiting for them to finish. Waiting would alter
// the observable behavior and render the test pointless.
func TestDeferAfterDo(t *testing.T) {
	var di DeferredInit
	var deferred, called atomic.Int32

	// deferOnce defers a test function once and fails the test
	// if [DeferredInit.Defer] returns true after [DeferredInit.Do]
	// has already been called and any deferred functions have been executed.
	// It's called concurrently by multiple goroutines.
	deferOnce := func() bool {
		// canDefer is whether it's acceptable for Defer to return true.
		// (but not it necessarily must return true)
		// If its func has run before, it's definitely not okay for it to
		// accept more Defer funcs.
		canDefer := called.Load() == 0
		ok := di.Defer(func() error {
			called.Add(1)
			return nil
		})
		if ok {
			if !canDefer {
				t.Error("An init function was deferred after DeferredInit.Do() was already called")
			}
			deferred.Add(1)
		}
		return ok
	}

	// Deferring a func before calling [DeferredInit.Do] should always succeed.
	if !deferOnce() {
		t.Fatal("Failed to defer a func")
	}

	// Defer up to N funcs concurrently while [DeferredInit.Do] is being called by the main goroutine.
	// Since we'll likely attempt to defer some funcs after [DeferredInit.Do] has been called,
	// we expect these late defers to fail, and the funcs will not be deferred or executed.
	// However, the number of the deferred and called funcs should always be equal when [DeferredInit.Do] exits.
	const N = 10000
	var wg sync.WaitGroup
	for range N {
		wg.Add(1)
		go func() {
			deferOnce()
			wg.Done()
		}()
	}

	if err := di.Do(); err != nil {
		t.Fatalf("DeferredInit.Do() failed: %v", err)
	}
	// The number of called funcs should remain unchanged after [DeferredInit.Do] returns.
	wantCalled := called.Load()

	if deferOnce() {
		t.Error("An init func was deferred after DeferredInit.Do() returned")
	}

	// Wait for the goroutines deferring init funcs to exit.
	// No funcs should be called after DeferredInit.Do() has returned,
	// and the number of called funcs should be equal to the number of deferred funcs.
	wg.Wait()
	if gotCalled := called.Load(); gotCalled != wantCalled {
		t.Errorf("An init func was called after DeferredInit.Do() returned. Got %d, want %d", gotCalled, wantCalled)
	}
	if deferred, called := deferred.Load(), called.Load(); deferred != called {
		t.Errorf("Deferred: %d; Called: %d", deferred, called)
	}
}

func checkError(tb testing.TB, got, want error, fatal bool) {
	tb.Helper()
	f := tb.Errorf
	if fatal {
		f = tb.Fatalf
	}
	if (want == nil && got != nil) ||
		(want != nil && got == nil) ||
		(want != nil && got != nil && want.Error() != got.Error()) {
		f("gotErr: %v; wantErr: %v", got, want)
	}
}

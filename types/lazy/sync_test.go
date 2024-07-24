// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lazy

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"tailscale.com/types/opt"
)

func TestSyncValue(t *testing.T) {
	var lt SyncValue[int]
	n := int(testing.AllocsPerRun(1000, func() {
		got := lt.Get(fortyTwo)
		if got != 42 {
			t.Fatalf("got %v; want 42", got)
		}
		if p, ok := lt.Peek(); !ok {
			t.Fatalf("Peek failed")
		} else if p != 42 {
			t.Fatalf("Peek got %v; want 42", p)
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

		if p, ok := lt.Peek(); !ok {
			t.Fatalf("Peek failed")
		} else if got != 0 {
			t.Fatalf("Peek got %v; want 0", p)
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
	if p, ok := lt.Peek(); !ok {
		t.Fatalf("Peek failed")
	} else if p != 42 {
		t.Fatalf("Peek got %v; want 42", p)
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

func TestSyncValueErrPeek(t *testing.T) {
	var sv SyncValue[int]
	sv.GetErr(func() (int, error) {
		return 123, errors.New("boom")
	})
	p, ok := sv.Peek()
	if ok {
		t.Error("unexpected Peek success")
	}
	if p != 0 {
		t.Fatalf("Peek got %v; want 0", p)
	}
	p, err, ok := sv.PeekErr()
	if !ok {
		t.Errorf("PeekErr ok=false; want true on error")
	}
	if got, want := fmt.Sprint(err), "boom"; got != want {
		t.Errorf("PeekErr error=%v; want %v", got, want)
	}
	if p != 123 {
		t.Fatalf("PeekErr got %v; want 123", p)
	}
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

func TestSyncValueSetForTest(t *testing.T) {
	testErr := errors.New("boom")
	tests := []struct {
		name            string
		initValue       opt.Value[int]
		initErr         opt.Value[error]
		setForTestValue int
		setForTestErr   error
		getValue        int
		getErr          opt.Value[error]
		wantValue       int
		wantErr         error
		routines        int
	}{
		{
			name:            "GetOk",
			setForTestValue: 42,
			getValue:        8,
			wantValue:       42,
		},
		{
			name:            "GetOk/WithInit",
			initValue:       opt.ValueOf(4),
			setForTestValue: 42,
			getValue:        8,
			wantValue:       42,
		},
		{
			name:            "GetOk/WithInitErr",
			initValue:       opt.ValueOf(4),
			initErr:         opt.ValueOf(errors.New("blast")),
			setForTestValue: 42,
			getValue:        8,
			wantValue:       42,
		},
		{
			name:            "GetErr",
			setForTestValue: 42,
			setForTestErr:   testErr,
			getValue:        8,
			getErr:          opt.ValueOf(errors.New("ka-boom")),
			wantValue:       42,
			wantErr:         testErr,
		},
		{
			name:            "GetErr/NilError",
			setForTestValue: 42,
			setForTestErr:   nil,
			getValue:        8,
			getErr:          opt.ValueOf(errors.New("ka-boom")),
			wantValue:       42,
			wantErr:         nil,
		},
		{
			name:            "GetErr/WithInitErr",
			initValue:       opt.ValueOf(4),
			initErr:         opt.ValueOf(errors.New("blast")),
			setForTestValue: 42,
			setForTestErr:   testErr,
			getValue:        8,
			getErr:          opt.ValueOf(errors.New("ka-boom")),
			wantValue:       42,
			wantErr:         testErr,
		},
		{
			name:            "Concurrent/GetOk",
			setForTestValue: 42,
			getValue:        8,
			wantValue:       42,
			routines:        10000,
		},
		{
			name:            "Concurrent/GetOk/WithInitErr",
			initValue:       opt.ValueOf(4),
			initErr:         opt.ValueOf(errors.New("blast")),
			setForTestValue: 42,
			getValue:        8,
			wantValue:       42,
			routines:        10000,
		},
		{
			name:            "Concurrent/GetErr",
			setForTestValue: 42,
			setForTestErr:   testErr,
			getValue:        8,
			getErr:          opt.ValueOf(errors.New("ka-boom")),
			wantValue:       42,
			wantErr:         testErr,
			routines:        10000,
		},
		{
			name:            "Concurrent/GetErr/WithInitErr",
			initValue:       opt.ValueOf(4),
			initErr:         opt.ValueOf(errors.New("blast")),
			setForTestValue: 42,
			setForTestErr:   testErr,
			getValue:        8,
			getErr:          opt.ValueOf(errors.New("ka-boom")),
			wantValue:       42,
			wantErr:         testErr,
			routines:        10000,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v SyncValue[int]

			// Initialize the sync value with the specified value and/or error,
			// if required by the test.
			if initValue, ok := tt.initValue.GetOk(); ok {
				var wantInitErr, gotInitErr error
				var wantInitValue, gotInitValue int
				wantInitValue = initValue
				if initErr, ok := tt.initErr.GetOk(); ok {
					wantInitErr = initErr
					gotInitValue, gotInitErr = v.GetErr(func() (int, error) { return initValue, initErr })
				} else {
					gotInitValue = v.Get(func() int { return initValue })
				}

				if gotInitErr != wantInitErr {
					t.Fatalf("InitErr: got %v; want %v", gotInitErr, wantInitErr)
				}
				if gotInitValue != wantInitValue {
					t.Fatalf("InitValue: got %v; want %v", gotInitValue, wantInitValue)
				}

				// Verify that SetForTest reverted the error and the value during the test cleanup.
				t.Cleanup(func() {
					wantCleanupValue, wantCleanupErr := wantInitValue, wantInitErr
					gotCleanupValue, gotCleanupErr, ok := v.PeekErr()
					if !ok {
						t.Fatal("SyncValue is not set after cleanup")
					}
					if gotCleanupErr != wantCleanupErr {
						t.Fatalf("CleanupErr: got %v; want %v", gotCleanupErr, wantCleanupErr)
					}
					if gotCleanupValue != wantCleanupValue {
						t.Fatalf("CleanupValue: got %v; want %v", gotCleanupValue, wantCleanupValue)
					}
				})
			} else {
				// Verify that if v wasn't set prior to SetForTest, it's
				// reverted to a valid unset state during the test cleanup.
				t.Cleanup(func() {
					if _, _, ok := v.PeekErr(); ok {
						t.Fatal("SyncValue is set after cleanup")
					}
					wantCleanupValue, wantCleanupErr := 42, errors.New("ka-boom")
					gotCleanupValue, gotCleanupErr := v.GetErr(func() (int, error) { return wantCleanupValue, wantCleanupErr })
					if gotCleanupErr != wantCleanupErr {
						t.Fatalf("CleanupErr: got %v; want %v", gotCleanupErr, wantCleanupErr)
					}
					if gotCleanupValue != wantCleanupValue {
						t.Fatalf("CleanupValue: got %v; want %v", gotCleanupValue, wantCleanupValue)
					}
				})
			}

			// Set the test value and/or error.
			v.SetForTest(t, tt.setForTestValue, tt.setForTestErr)

			// Verify that the value and/or error have been set.
			// This will run on either the current goroutine
			// or concurrently depending on the tt.routines value.
			checkSyncValue := func() {
				var gotValue int
				var gotErr error
				if getErr, ok := tt.getErr.GetOk(); ok {
					gotValue, gotErr = v.GetErr(func() (int, error) { return tt.getValue, getErr })
				} else {
					gotValue = v.Get(func() int { return tt.getValue })
				}

				if gotErr != tt.wantErr {
					t.Errorf("Err: got %v; want %v", gotErr, tt.wantErr)
				}
				if gotValue != tt.wantValue {
					t.Errorf("Value: got %v; want %v", gotValue, tt.wantValue)
				}
			}

			switch tt.routines {
			case 0:
				checkSyncValue()
			default:
				var wg sync.WaitGroup
				wg.Add(tt.routines)
				start := make(chan struct{})
				for range tt.routines {
					go func() {
						defer wg.Done()
						// Every goroutine waits for the go signal, so that more of them
						// have a chance to race on the initial Get than with sequential
						// goroutine starts.
						<-start
						checkSyncValue()
					}()
				}
				close(start)
				wg.Wait()
			}
		})
	}
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

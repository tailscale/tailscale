// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package reload

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tstest"
)

func TestReloader(t *testing.T) {
	buf := []byte("hello world")

	ctx := context.Background()
	r, err := newUnstarted[string](ctx, ReloadOpts[string]{
		Logf: t.Logf,
		Read: func(context.Context) ([]byte, error) {
			return buf, nil
		},
		Unmarshal: func(b []byte) (string, error) {
			return "The value is: " + string(b), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// We should have an initial value.
	const wantInitial = "The value is: hello world"
	if v := r.store.Load(); v != wantInitial {
		t.Errorf("got initial value %q, want %q", v, wantInitial)
	}

	// Reloading should result in a new value
	buf = []byte("new value")
	if err := r.updateOnce(); err != nil {
		t.Fatal(err)
	}

	const wantReload = "The value is: new value"
	if v := r.store.Load(); v != wantReload {
		t.Errorf("got reloaded value %q, want %q", v, wantReload)
	}
}

func TestReloader_InitialError(t *testing.T) {
	fakeErr := errors.New("fake error")

	ctx := context.Background()
	_, err := newUnstarted[string](ctx, ReloadOpts[string]{
		Logf:      t.Logf,
		Read:      func(context.Context) ([]byte, error) { return nil, fakeErr },
		Unmarshal: func(b []byte) (string, error) { panic("unused because Read fails") },
	})
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !errors.Is(err, fakeErr) {
		t.Errorf("wanted errors.Is(%v, fakeErr)=true", err)
	}
}

func TestReloader_ReloadError(t *testing.T) {
	fakeErr := errors.New("fake error")
	shouldError := false

	ctx := context.Background()
	r, err := newUnstarted[string](ctx, ReloadOpts[string]{
		Logf: t.Logf,
		Read: func(context.Context) ([]byte, error) {
			return []byte("hello"), nil
		},
		Unmarshal: func(b []byte) (string, error) {
			if shouldError {
				return "", fakeErr
			}
			return string(b), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.store.Load(); got != "hello" {
		t.Fatalf("got value %q, want \"hello\"", got)
	}

	shouldError = true

	if err := r.updateOnce(); err == nil {
		t.Errorf("expected error from updateOnce")
	}
	if got := r.store.Load(); got != "hello" {
		t.Fatalf("got value %q, want \"hello\"", got)
	}
}

func TestReloader_Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var ncalls atomic.Int64
	load, err := New[string](ctx, ReloadOpts[string]{
		Logf:     tstest.WhileTestRunningLogger(t),
		Interval: 10 * time.Millisecond,
		Read: func(context.Context) ([]byte, error) {
			return []byte("hello"), nil
		},
		Unmarshal: func(b []byte) (string, error) {
			callNum := ncalls.Add(1)
			if callNum == 3 {
				cancel()
			}
			return fmt.Sprintf("call %d: %s", callNum, b), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "call 1: hello"
	if got := load(); got != want {
		t.Fatalf("got value %q, want %q", got, want)
	}

	// Wait for the periodic refresh to cancel our context
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("test timed out")
	}

	// Depending on how goroutines get scheduled, we can either read call 2
	// (if we woke up before the run goroutine stores call 3), or call 3
	// (if we woke up after the run goroutine stores the next value). Check
	// for both.
	want1, want2 := "call 2: hello", "call 3: hello"
	if got := load(); got != want1 && got != want2 {
		t.Fatalf("got value %q, want %q or %q", got, want1, want2)
	}
}

func TestFromJSONFile(t *testing.T) {
	type testStruct struct {
		Value  string
		Number int
	}
	fpath := filepath.Join(t.TempDir(), "test.json")
	if err := os.WriteFile(fpath, []byte(`{"Value": "hello", "Number": 1234}`), 0600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	r, err := newUnstarted(ctx, FromJSONFile[*testStruct](fpath))
	if err != nil {
		t.Fatal(err)
	}

	got := r.store.Load()
	want := &testStruct{Value: "hello", Number: 1234}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

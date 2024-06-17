// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package singleflight

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDo(t *testing.T) {
	var g Group[string, any]
	v, err, _ := g.Do("key", func() (interface{}, error) {
		return "bar", nil
	})
	if got, want := fmt.Sprintf("%v (%T)", v, v), "bar (string)"; got != want {
		t.Errorf("Do = %v; want %v", got, want)
	}
	if err != nil {
		t.Errorf("Do error = %v", err)
	}
}

func TestDoErr(t *testing.T) {
	var g Group[string, any]
	someErr := errors.New("Some error")
	v, err, _ := g.Do("key", func() (interface{}, error) {
		return nil, someErr
	})
	if err != someErr {
		t.Errorf("Do error = %v; want someErr %v", err, someErr)
	}
	if v != nil {
		t.Errorf("unexpected non-nil value %#v", v)
	}
}

func TestDoDupSuppress(t *testing.T) {
	var g Group[string, any]
	var wg1, wg2 sync.WaitGroup
	c := make(chan string, 1)
	var calls int32
	fn := func() (interface{}, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			// First invocation.
			wg1.Done()
		}
		v := <-c
		c <- v // pump; make available for any future calls

		time.Sleep(10 * time.Millisecond) // let more goroutines enter Do

		return v, nil
	}

	const n = 10
	wg1.Add(1)
	for range n {
		wg1.Add(1)
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			wg1.Done()
			v, err, _ := g.Do("key", fn)
			if err != nil {
				t.Errorf("Do error: %v", err)
				return
			}
			if s, _ := v.(string); s != "bar" {
				t.Errorf("Do = %T %v; want %q", v, v, "bar")
			}
		}()
	}
	wg1.Wait()
	// At least one goroutine is in fn now and all of them have at
	// least reached the line before the Do.
	c <- "bar"
	wg2.Wait()
	if got := atomic.LoadInt32(&calls); got <= 0 || got >= n {
		t.Errorf("number of calls = %d; want over 0 and less than %d", got, n)
	}
}

// Test that singleflight behaves correctly after Forget called.
// See https://github.com/golang/go/issues/31420
func TestForget(t *testing.T) {
	var g Group[string, any]

	var (
		firstStarted  = make(chan struct{})
		unblockFirst  = make(chan struct{})
		firstFinished = make(chan struct{})
	)

	go func() {
		g.Do("key", func() (i interface{}, e error) {
			close(firstStarted)
			<-unblockFirst
			close(firstFinished)
			return
		})
	}()
	<-firstStarted
	g.Forget("key")

	unblockSecond := make(chan struct{})
	secondResult := g.DoChan("key", func() (i interface{}, e error) {
		<-unblockSecond
		return 2, nil
	})

	close(unblockFirst)
	<-firstFinished

	thirdResult := g.DoChan("key", func() (i interface{}, e error) {
		return 3, nil
	})

	close(unblockSecond)
	<-secondResult
	r := <-thirdResult
	if r.Val != 2 {
		t.Errorf("We should receive result produced by second call, expected: 2, got %d", r.Val)
	}
}

func TestDoChan(t *testing.T) {
	var g Group[string, any]
	ch := g.DoChan("key", func() (interface{}, error) {
		return "bar", nil
	})

	res := <-ch
	v := res.Val
	err := res.Err
	if got, want := fmt.Sprintf("%v (%T)", v, v), "bar (string)"; got != want {
		t.Errorf("Do = %v; want %v", got, want)
	}
	if err != nil {
		t.Errorf("Do error = %v", err)
	}
}

// Test singleflight behaves correctly after Do panic.
// See https://github.com/golang/go/issues/41133
func TestPanicDo(t *testing.T) {
	var g Group[string, any]
	fn := func() (interface{}, error) {
		panic("invalid memory address or nil pointer dereference")
	}

	const n = 5
	waited := int32(n)
	panicCount := int32(0)
	done := make(chan struct{})
	for range n {
		go func() {
			defer func() {
				if err := recover(); err != nil {
					t.Logf("Got panic: %v\n%s", err, debug.Stack())
					atomic.AddInt32(&panicCount, 1)
				}

				if atomic.AddInt32(&waited, -1) == 0 {
					close(done)
				}
			}()

			g.Do("key", fn)
		}()
	}

	select {
	case <-done:
		if panicCount != n {
			t.Errorf("Expect %d panic, but got %d", n, panicCount)
		}
	case <-time.After(time.Second):
		t.Fatalf("Do hangs")
	}
}

func TestGoexitDo(t *testing.T) {
	var g Group[string, any]
	fn := func() (interface{}, error) {
		runtime.Goexit()
		return nil, nil
	}

	const n = 5
	waited := int32(n)
	done := make(chan struct{})
	for range n {
		go func() {
			var err error
			defer func() {
				if err != nil {
					t.Errorf("Error should be nil, but got: %v", err)
				}
				if atomic.AddInt32(&waited, -1) == 0 {
					close(done)
				}
			}()
			_, err, _ = g.Do("key", fn)
		}()
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("Do hangs")
	}
}

func TestPanicDoChan(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skipf("js does not support exec")
	}

	if os.Getenv("TEST_PANIC_DOCHAN") != "" {
		defer func() {
			recover()
		}()

		g := new(Group[string, any])
		ch := g.DoChan("", func() (interface{}, error) {
			panic("Panicking in DoChan")
		})
		<-ch
		t.Fatalf("DoChan unexpectedly returned")
	}

	t.Parallel()

	cmd := exec.Command(os.Args[0], "-test.run="+t.Name(), "-test.v")
	cmd.Env = append(os.Environ(), "TEST_PANIC_DOCHAN=1")
	out := new(bytes.Buffer)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	err := cmd.Wait()
	t.Logf("%s:\n%s", strings.Join(cmd.Args, " "), out)
	if err == nil {
		t.Errorf("Test subprocess passed; want a crash due to panic in DoChan")
	}
	if bytes.Contains(out.Bytes(), []byte("DoChan unexpectedly")) {
		t.Errorf("Test subprocess failed with an unexpected failure mode.")
	}
	if !bytes.Contains(out.Bytes(), []byte("Panicking in DoChan")) {
		t.Errorf("Test subprocess failed, but the crash isn't caused by panicking in DoChan")
	}
}

func TestPanicDoSharedByDoChan(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skipf("js does not support exec")
	}

	if os.Getenv("TEST_PANIC_DOCHAN") != "" {
		blocked := make(chan struct{})
		unblock := make(chan struct{})

		g := new(Group[string, any])
		go func() {
			defer func() {
				recover()
			}()
			g.Do("", func() (interface{}, error) {
				close(blocked)
				<-unblock
				panic("Panicking in Do")
			})
		}()

		<-blocked
		ch := g.DoChan("", func() (interface{}, error) {
			panic("DoChan unexpectedly executed callback")
		})
		close(unblock)
		<-ch
		t.Fatalf("DoChan unexpectedly returned")
	}

	t.Parallel()

	cmd := exec.Command(os.Args[0], "-test.run="+t.Name(), "-test.v")
	cmd.Env = append(os.Environ(), "TEST_PANIC_DOCHAN=1")
	out := new(bytes.Buffer)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	err := cmd.Wait()
	t.Logf("%s:\n%s", strings.Join(cmd.Args, " "), out)
	if err == nil {
		t.Errorf("Test subprocess passed; want a crash due to panic in Do shared by DoChan")
	}
	if bytes.Contains(out.Bytes(), []byte("DoChan unexpectedly")) {
		t.Errorf("Test subprocess failed with an unexpected failure mode.")
	}
	if !bytes.Contains(out.Bytes(), []byte("Panicking in Do")) {
		t.Errorf("Test subprocess failed, but the crash isn't caused by panicking in Do")
	}
}

func TestDoChanContext(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var g Group[string, int]
		ch := g.DoChanContext(ctx, "key", func(_ context.Context) (int, error) {
			return 1, nil
		})
		ret := <-ch
		assertOKResult(t, ret, 1)
	})

	t.Run("DoesNotPropagateValues", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		key := new(int)
		const value = "hello world"

		ctx = context.WithValue(ctx, key, value)

		var g Group[string, int]
		ch := g.DoChanContext(ctx, "foobar", func(ctx context.Context) (int, error) {
			if _, ok := ctx.Value(key).(string); ok {
				t.Error("expected no value, but was present in context")
			}
			return 1, nil
		})
		ret := <-ch
		assertOKResult(t, ret, 1)
	})

	t.Run("NoCancelWhenWaiters", func(t *testing.T) {
		testCtx, testCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer testCancel()

		trigger := make(chan struct{})

		ctx1, cancel1 := context.WithCancel(context.Background())
		defer cancel1()
		ctx2, cancel2 := context.WithCancel(context.Background())
		defer cancel2()

		fn := func(ctx context.Context) (int, error) {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-trigger:
				return 1234, nil
			}
		}

		// Create two waiters, then cancel the first before we trigger
		// the function to return a value. This shouldn't result in a
		// context canceled error.
		var g Group[string, int]
		ch1 := g.DoChanContext(ctx1, "key", fn)
		ch2 := g.DoChanContext(ctx2, "key", fn)

		cancel1()

		// The first channel, now that it's canceled, should return a
		// context canceled error.
		select {
		case res := <-ch1:
			if !errors.Is(res.Err, context.Canceled) {
				t.Errorf("unexpected error; got %v, want context.Canceled", res.Err)
			}
		case <-testCtx.Done():
			t.Fatal("test timed out")
		}

		// Actually return
		close(trigger)
		res := <-ch2
		assertOKResult(t, res, 1234)
	})

	t.Run("AllCancel", func(t *testing.T) {
		for _, n := range []int{1, 2, 10, 20} {
			t.Run(fmt.Sprintf("NumWaiters=%d", n), func(t *testing.T) {
				testCtx, testCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer testCancel()

				trigger := make(chan struct{})
				defer close(trigger)

				fn := func(ctx context.Context) (int, error) {
					select {
					case <-ctx.Done():
						return 0, ctx.Err()
					case <-trigger:
						t.Error("unexpected trigger; want all callers to cancel")
						return 0, errors.New("unexpected trigger")
					}
				}

				// Launch N goroutines that all wait on the same key.
				var (
					g       Group[string, int]
					chs     []<-chan Result[int]
					cancels []context.CancelFunc
				)
				for i := range n {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					cancels = append(cancels, cancel)

					ch := g.DoChanContext(ctx, "key", fn)
					chs = append(chs, ch)

					// Every third goroutine should cancel
					// immediately, which better tests the
					// cancel logic.
					if i%3 == 0 {
						cancel()
					}
				}

				// Now that everything is waiting, cancel all the contexts.
				for _, cancel := range cancels {
					cancel()
				}

				// Wait for a result from each channel. They
				// should all return an error showing a context
				// cancel.
				for _, ch := range chs {
					select {
					case res := <-ch:
						if !errors.Is(res.Err, context.Canceled) {
							t.Errorf("unexpected error; got %v, want context.Canceled", res.Err)
						}
					case <-testCtx.Done():
						t.Fatal("test timed out")
					}
				}
			})
		}
	})
}

func assertOKResult[V comparable](t testing.TB, res Result[V], want V) {
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if res.Val != want {
		t.Fatalf("unexpected value; got %v, want %v", res.Val, want)
	}
}

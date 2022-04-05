// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logger

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"sync"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"tailscale.com/tailcfg"
)

func TestFuncWriter(t *testing.T) {
	w := FuncWriter(t.Logf)
	lg := log.New(w, "prefix: ", 0)
	lg.Printf("plumbed through")
}

func TestStdLogger(t *testing.T) {
	lg := StdLogger(t.Logf)
	lg.Printf("plumbed through")
}

func logTester(want []string, t *testing.T, i *int) Logf {
	return func(format string, args ...any) {
		got := fmt.Sprintf(format, args...)
		if *i >= len(want) {
			t.Fatalf("Logging continued past end of expected input: %s", got)
		}
		if got != want[*i] {
			t.Fatalf("\nwanted: %s\n   got: %s", want[*i], got)
		}
		t.Log(got)
		*i++
	}
}

func TestRateLimiter(t *testing.T) {
	want := []string{
		"boring string with constant formatting (constant)",
		"templated format string no. 0",
		"boring string with constant formatting (constant)",
		"[RATELIMIT] format(\"boring string with constant formatting %s\")",
		"templated format string no. 1",
		"[RATELIMIT] format(\"templated format string no. %d\")",
		"Make sure this string makes it through the rest (that are blocked) 4",
		"4 shouldn't get filtered.",
		"hello 1",
		"hello 2",
		"[RATELIMIT] format(\"hello %v\")",
		"[RATELIMIT] format(\"hello %v\") (2 dropped)",
		"hello 5",
		"hello 6",
		"[RATELIMIT] format(\"hello %v\")",
		"hello 7",
	}

	var now time.Time
	nowf := func() time.Time { return now }

	testsRun := 0
	lgtest := logTester(want, t, &testsRun)
	lg := RateLimitedFnWithClock(lgtest, 1*time.Minute, 2, 50, nowf)
	var prefixed Logf
	for i := 0; i < 10; i++ {
		lg("boring string with constant formatting %s", "(constant)")
		lg("templated format string no. %d", i)
		if i == 4 {
			lg("Make sure this string makes it through the rest (that are blocked) %d", i)
			prefixed = WithPrefix(lg, string(rune('0'+i)))
			prefixed(" shouldn't get filtered.")
		}
	}

	lg("hello %v", 1)
	lg("hello %v", 2) // printed, but rate limit starts
	lg("hello %v", 3) // rate limited (not printed)
	now = now.Add(1 * time.Minute)
	lg("hello %v", 4) // still limited (not printed)
	now = now.Add(1 * time.Minute)
	lg("hello %v", 5) // restriction lifted; prints drop count + message

	lg("hello %v", 6) // printed, but rate limit starts
	now = now.Add(2 * time.Minute)
	lg("hello %v", 7) // restriction lifted; no drop count needed

	if testsRun < len(want) {
		t.Fatalf("Tests after %s weren't logged.", want[testsRun])
	}

}

func testTimer(d time.Duration) func() time.Time {
	timeNow := time.Now()
	return func() time.Time {
		timeNow = timeNow.Add(d)
		return timeNow
	}
}

func TestLogOnChange(t *testing.T) {
	want := []string{
		"1 2 3 4 5 6",
		"1 2 3 4 5 6",
		"1 2 3 4 5 7",
		"1 2 3 4 5",
		"1 2 3 4 5 6 7",
	}

	timeNow := testTimer(1 * time.Second)

	testsRun := 0
	lgtest := logTester(want, t, &testsRun)
	lg := LogOnChange(lgtest, 5*time.Second, timeNow)

	for i := 0; i < 10; i++ {
		lg("%s", "1 2 3 4 5 6")
	}
	lg("1 2 3 4 5 7")
	lg("1 2 3 4 5")
	lg("1 2 3 4 5")
	lg("1 2 3 4 5 6 7")

	if testsRun < len(want) {
		t.Fatalf("'Wanted' lines including and after [%s] weren't logged.", want[testsRun])
	}
}

func TestArgWriter(t *testing.T) {
	got := new(bytes.Buffer)
	fmt.Fprintf(got, "Greeting: %v", ArgWriter(func(bw *bufio.Writer) {
		bw.WriteString("Hello, ")
		bw.WriteString("world")
		bw.WriteByte('!')
	}))
	const want = "Greeting: Hello, world!"
	if got.String() != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestSynchronization(t *testing.T) {
	timeNow := testTimer(1 * time.Second)
	tests := []struct {
		name string
		logf Logf
	}{
		{"RateLimitedFn", RateLimitedFn(t.Logf, 1*time.Minute, 2, 50)},
		{"LogOnChange", LogOnChange(t.Logf, 5*time.Second, timeNow)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wg sync.WaitGroup
			wg.Add(2)

			f := func() {
				tt.logf("1 2 3 4 5")
				wg.Done()
			}

			go f()
			go f()

			wg.Wait()
		})
	}
}

// test that RateLimitedFn is safe for reentrancy without deadlocking
func TestRateLimitedFnReentrancy(t *testing.T) {
	rlogf := RateLimitedFn(t.Logf, time.Nanosecond, 10, 10)
	rlogf("Hello.")
	rlogf("Hello, %v", ArgWriter(func(bw *bufio.Writer) {
		bw.WriteString("world")
	}))
	rlogf("Hello, %v", ArgWriter(func(bw *bufio.Writer) {
		bw.WriteString("bye")
		rlogf("boom") // this used to deadlock
	}))
}

func TestContext(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	// Test that FromContext returns log.Printf when the context has no custom log function.
	defer log.SetOutput(log.Writer())
	defer log.SetFlags(log.Flags())
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0)
	logf := FromContext(ctx)
	logf("a")
	c.Assert(buf.String(), qt.Equals, "a\n")

	// Test that FromContext and Ctx work together.
	var called bool
	markCalled := func(string, ...any) {
		called = true
	}
	ctx = Ctx(ctx, markCalled)
	logf = FromContext(ctx)
	logf("a")
	c.Assert(called, qt.IsTrue)
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	var logf Logf = func(f string, a ...any) { fmt.Fprintf(&buf, f, a...) }
	logf.JSON(1, "foo", &tailcfg.Hostinfo{})
	want := "[v\x00JSON]1" + `{"foo":{}}`
	if got := buf.String(); got != want {
		t.Errorf("mismatch\n got: %q\nwant: %q\n", got, want)
	}
}

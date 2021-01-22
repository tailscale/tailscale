// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logger

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"sync"
	"testing"
	"time"
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
	return func(format string, args ...interface{}) {
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
		"templated format string no. 1",
		"[RATE LIMITED] format string \"boring string with constant formatting %s\" (example: \"boring string with constant formatting (constant)\")",
		"[RATE LIMITED] format string \"templated format string no. %d\" (example: \"templated format string no. 2\")",
		"Make sure this string makes it through the rest (that are blocked) 4",
		"4 shouldn't get filtered.",
	}

	testsRun := 0
	lgtest := logTester(want, t, &testsRun)
	lg := RateLimitedFn(lgtest, 1*time.Minute, 2, 50)
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
	if testsRun < len(want) {
		t.Fatalf("Tests after %s weren't logged.", want[testsRun])
	}
}

func TestNoRateLimit(t *testing.T) {
	want := []string{
		"not rate limited",
		"rate limited",
		"not rate limited",
		"[RATE LIMITED] format string \"rate limited\" (example: \"rate limited\")",
		"not rate limited",
		"not rate limited",
		"not rate limited",
	}

	testsRun := 0
	lgtest := logTester(want, t, &testsRun)
	rl := RateLimitedFn(lgtest, 1*time.Minute, 1, 1)
	lg := NoRateLimit(rl)
	for i := 0; i < 5; i++ {
		lg("not rate limited")
		rl("rate limited")
	}
	if testsRun < len(want) {
		t.Fatalf("tests after %s weren't logged.", want[testsRun])
	}
}

func TestRateLimitContext(t *testing.T) {
	want := []string{
		"x",
		"[RATE LIMITED] format string \"x (rate-limit-context:A)\" (example: \"x\")",
		"x",
	}

	testsRun := 0
	lgtest := logTester(want, t, &testsRun)
	rl := RateLimitedFn(lgtest, 1*time.Minute, 1, 1)
	a := RateLimitContext(rl, "A")
	b := RateLimitContext(rl, "B")
	a("x")
	a("x")
	b("x") // this is not rate-limited despite the identical format string, because it has a different rate-limit context
	if testsRun < len(want) {
		t.Fatalf("tests after %s weren't logged.", want[testsRun])
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

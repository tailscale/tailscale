// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logger

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
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
			t.Fatalf("wanted: %s \n got: %s", want[*i], got)
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
		"Repeated messages were suppressed by rate limiting. Original message: boring string with constant formatting (constant)",
		"Repeated messages were suppressed by rate limiting. Original message: templated format string no. 2",
		"Make sure this string makes it through the rest (that are blocked) 4",
		"4 shouldn't get filtered.",
	}

	testsRun := 0
	lgtest := logTester(want, t, &testsRun)
	lg := RateLimitedFn(lgtest, 1*time.Second, 2, 50)
	var prefixed Logf
	for i := 0; i < 10; i++ {
		lg("boring string with constant formatting %s", "(constant)")
		lg("templated format string no. %d", i)
		if i == 4 {
			lg("Make sure this string makes it through the rest (that are blocked) %d", i)
			prefixed = WithPrefix(lg, string('0'+i))
			prefixed(" shouldn't get filtered.")
		}
	}
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

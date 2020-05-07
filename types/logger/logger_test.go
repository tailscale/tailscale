// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logger

import (
	"fmt"
	"log"
	"testing"
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

func TestRateLimiter(t *testing.T) {

	// Testing function. args[0] should indicate what should
	logTester := func(want []string) Logf {
		i := 0
		return func(format string, args ...interface{}) {
			got := fmt.Sprintf(format, args...)
			if i >= len(want) {
				t.Fatalf("Logging continued past end of expected input: %s", got)
			}
			if got != want[i] {
				t.Fatalf("wanted: %s \n got: %s", want[i], got)
			}
			i++
		}
	}

	want := []string{
		"boring string with constant formatting (constant)",
		"templated format string no. 0",
		"Repeated messages were suppressed by rate limiting. Original message: boring string with constant formatting (constant)",
		"Repeated messages were suppressed by rate limiting. Original message: templated format string no. 1",
		"Make sure this string makes it through the rest (that are blocked) 4",
		"4 shouldn't get filtered.",
	}

	lg := RateLimitedFn(logTester(want), 1, 1, 50)
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

}

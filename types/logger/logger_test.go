// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logger

import (
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

func TestRateLimiter(t *testing.T) {
	lg := RateLimitedFn(t.Logf, 1, 1)
	var prefixed Logf
	for i := 0; i < 10; i++ {
		lg("boring string with no formatting")
		lg("templated format string no. %d", i)
		if i == 4 {
			lg("Make sure this string makes it through the rest (that are blocked) %d", i)
		}
		prefixed = WithPrefix(lg, string('0'+i))
		prefixed(" shouldn't get filtered.")
		time.Sleep(200 * time.Millisecond)
	}

}

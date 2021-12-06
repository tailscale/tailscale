// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package progress

import (
	"bytes"
	"io"
	"log"
	"strings"
	"testing"
	"time"
)

func TestReader(t *testing.T) {
	sig := make(chan time.Time)
	newTicker = func(d time.Duration) *time.Ticker {
		tk := time.NewTicker(d)
		tk.C = sig
		t.Cleanup(func() { tk.Stop() })
		return tk
	}
	t.Cleanup(func() {
		newTicker = time.NewTicker
	})

	// capture log output
	oldw := log.Writer()
	oldf := log.Flags()
	t.Cleanup(func() {
		log.SetOutput(oldw)
		log.SetFlags(oldf)
	})
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0)

	rdr := New(strings.NewReader("test data here"), 14, time.Second)

	// before we copy, we print 0
	sig <- time.Time{}

	// copy all data, then finish
	io.Copy(io.Discard, rdr)
	rdr.Close()

	const expected = "progress: 0 / 14 bytes (0.00%)\nprogress: 14 bytes (finished)\n"
	if got := buf.String(); got != expected {
		t.Errorf("mismatch in progress ouptut\nexpected: %q\ngot: %q\n", expected, got)
	}
}

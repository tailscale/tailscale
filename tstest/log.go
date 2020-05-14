// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstest

import (
	"log"
	"os"
	"testing"
)

type testLogWriter struct {
	t *testing.T
}

func (w *testLogWriter) Write(b []byte) (int, error) {
	w.t.Helper()
	w.t.Logf("%s", b)
	return len(b), nil
}

func FixLogs(t *testing.T) {
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.SetOutput(&testLogWriter{t})
}

func UnfixLogs(t *testing.T) {
	defer log.SetOutput(os.Stderr)
}

type panicLogWriter struct {
	t *testing.T
}

func (w *panicLogWriter) Write(b []byte) (int, error) {
	panic("please use tailscale.com/logger.Logf instead of the log module")
}

func PanicOnLog() {
	log.SetOutput(&panicLogWriter{})
}

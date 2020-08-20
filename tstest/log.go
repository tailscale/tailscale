// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstest

import (
	"log"
	"os"
	"sync"
	"testing"

	"tailscale.com/types/logger"
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

type panicLogWriter struct{}

func (panicLogWriter) Write(b []byte) (int, error) {
	panic("please use tailscale.com/logger.Logf instead of the log package")
}

// PanicOnLog modifies the standard library log package's default output to
// an io.Writer that panics, to root out code that's not plumbing their logging
// through explicit tailscale.com/logger.Logf paths.
func PanicOnLog() {
	log.SetOutput(panicLogWriter{})
}

// ListenFor produces a LogListener wrapping a given logf with the given logStrings
func ListenFor(logf logger.Logf, logStrings []string) *LogListener {
	ret := LogListener{
		logf:      logf,
		listenFor: logStrings,
		seen:      make(map[string]bool),
	}
	for _, line := range logStrings {
		ret.seen[line] = false
	}
	return &ret
}

// LogListener takes a list of log lines to listen for
type LogListener struct {
	logf      logger.Logf
	listenFor []string

	mu   sync.Mutex
	seen map[string]bool
}

// Logf records and logs a given line
func (ll *LogListener) Logf(format string, args ...interface{}) {
	ll.mu.Lock()
	if _, ok := ll.seen[format]; ok {
		ll.seen[format] = true
	}
	ll.mu.Unlock()
	ll.logf(format, args)
}

// Check returns which lines haven't been logged yet
func (ll *LogListener) Check() []string {
	ll.mu.Lock()
	defer ll.mu.Unlock()
	var notSeen []string
	for _, line := range ll.listenFor {
		if !ll.seen[line] {
			notSeen = append(notSeen, line)
		}
	}
	return notSeen
}

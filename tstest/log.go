// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstest

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"sync"
	"testing"

	"go4.org/mem"
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
	// Allow certain phrases for now, in the interest of getting
	// CI working on Windows and not having to refactor all the
	// interfaces.GetState & tshttpproxy code to allow pushing
	// down a Logger yet. TODO(bradfitz): do that refactoring once
	// 1.2.0 is out.
	if bytes.Contains(b, []byte("tshttpproxy: ")) {
		os.Stderr.Write(b)
		return len(b), nil
	}
	panic(fmt.Sprintf("please use tailscale.com/logger.Logf instead of the log package (tried to log: %q)", b))
}

// PanicOnLog modifies the standard library log package's default output to
// an io.Writer that panics, to root out code that's not plumbing their logging
// through explicit tailscale.com/logger.Logf paths.
func PanicOnLog() {
	log.SetOutput(panicLogWriter{})
}

// NewLogLineTracker produces a LogLineTracker wrapping a given logf that tracks whether expectedFormatStrings were seen.
func NewLogLineTracker(logf logger.Logf, expectedFormatStrings []string) *LogLineTracker {
	ret := &LogLineTracker{
		logf:      logf,
		listenFor: expectedFormatStrings,
		seen:      make(map[string]bool),
	}
	for _, line := range expectedFormatStrings {
		ret.seen[line] = false
	}
	return ret
}

// LogLineTracker is a logger that tracks which log format patterns it's
// seen and can report which expected ones were not seen later.
type LogLineTracker struct {
	logf      logger.Logf
	listenFor []string

	mu     sync.Mutex
	closed bool
	seen   map[string]bool // format string => false (if not yet seen but wanted) or true (once seen)
}

// Logf logs to its underlying logger and also tracks that the given format pattern has been seen.
func (lt *LogLineTracker) Logf(format string, args ...interface{}) {
	lt.mu.Lock()
	if lt.closed {
		lt.mu.Unlock()
		return
	}
	if v, ok := lt.seen[format]; ok && !v {
		lt.seen[format] = true
	}
	lt.mu.Unlock()
	lt.logf(format, args...)
}

// Check returns which format strings haven't been logged yet.
func (lt *LogLineTracker) Check() []string {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	var notSeen []string
	for _, format := range lt.listenFor {
		if !lt.seen[format] {
			notSeen = append(notSeen, format)
		}
	}
	return notSeen
}

// Reset forgets everything that it's seen.
func (lt *LogLineTracker) Reset() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	for _, line := range lt.listenFor {
		lt.seen[line] = false
	}
}

// Close closes lt. After calling Close, calls to Logf become no-ops.
func (lt *LogLineTracker) Close() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.closed = true
}

// MemLogger is a bytes.Buffer with a Logf method for tests that want
// to log to a buffer.
type MemLogger struct {
	sync.Mutex
	bytes.Buffer
}

func (ml *MemLogger) Logf(format string, args ...interface{}) {
	ml.Lock()
	defer ml.Unlock()
	fmt.Fprintf(&ml.Buffer, format, args...)
	if !mem.HasSuffix(mem.B(ml.Buffer.Bytes()), mem.S("\n")) {
		ml.Buffer.WriteByte('\n')
	}
}

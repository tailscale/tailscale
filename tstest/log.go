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
func (lt *LogLineTracker) Logf(format string, args ...any) {
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

func (ml *MemLogger) Logf(format string, args ...any) {
	ml.Lock()
	defer ml.Unlock()
	fmt.Fprintf(&ml.Buffer, format, args...)
	if !mem.HasSuffix(mem.B(ml.Buffer.Bytes()), mem.S("\n")) {
		ml.Buffer.WriteByte('\n')
	}
}

func (ml *MemLogger) String() string {
	ml.Lock()
	defer ml.Unlock()
	return ml.Buffer.String()
}

// WhileTestRunningLogger returns a logger.Logf that logs to t.Logf until the
// test finishes, at which point it no longer logs anything.
func WhileTestRunningLogger(t testing.TB) logger.Logf {
	var (
		mu   sync.RWMutex
		done bool
	)

	logger := func(format string, args ...any) {
		t.Helper()

		mu.RLock()
		defer mu.RUnlock()

		if done {
			return
		}
		t.Logf(format, args...)
	}

	// t.Cleanup is run before the test is marked as done, so by acquiring
	// the mutex and then disabling logs, we know that all existing log
	// functions have completed, and that no future calls to the logger
	// will log something.
	//
	// We can't do this with an atomic bool, since it's possible to
	// observe the following race:
	//
	//    test goroutine                goroutine 1
	//    --------------                -----------
	//                                  check atomic, testFinished = no
	//    test finishes
	//    run t.Cleanups
	//    set testFinished = true
	//                                  call t.Logf
	//                                  panic
	//
	// Using a mutex ensures that all actions in goroutine 1 in the
	// sequence above occur atomically, and thus should not panic.
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		done = true
	})
	return logger
}

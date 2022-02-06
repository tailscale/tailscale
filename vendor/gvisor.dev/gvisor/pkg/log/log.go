// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package log implements a library for logging.
//
// This is separate from the standard logging package because logging may be a
// high-impact activity, and therefore we wanted to provide as much flexibility
// as possible in the underlying implementation.
//
// Note that logging should still be considered high-impact, and should not be
// done in the hot path. If necessary, logging statements should be protected
// with guards regarding the logging level. For example,
//
//	if log.IsLogging(log.Debug) {
//		log.Debugf(...)
//	}
//
// This is because the log.Debugf(...) statement alone will generate a
// significant amount of garbage and churn in many cases, even if no log
// message is ultimately emitted.
package log

import (
	"fmt"
	"io"
	stdlog "log"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/linewriter"
	"gvisor.dev/gvisor/pkg/sync"
)

// Level is the log level.
type Level uint32

// The following levels are fixed, and can never be changed. Since some control
// RPCs allow for changing the level as an integer, it is only possible to add
// additional levels, and the existing one cannot be removed.
const (
	// Warning indicates that output should always be emitted.
	Warning Level = iota

	// Info indicates that output should normally be emitted.
	Info

	// Debug indicates that output should not normally be emitted.
	Debug
)

func (l Level) String() string {
	switch l {
	case Warning:
		return "Warning"
	case Info:
		return "Info"
	case Debug:
		return "Debug"
	default:
		return fmt.Sprintf("Invalid level: %d", l)
	}
}

// Emitter is the final destination for logs.
type Emitter interface {
	// Emit emits the given log statement. This allows for control over the
	// timestamp used for logging.
	Emit(depth int, level Level, timestamp time.Time, format string, v ...interface{})
}

// Writer writes the output to the given writer.
type Writer struct {
	// Next is where output is written.
	Next io.Writer

	// mu protects fields below.
	mu sync.Mutex

	// errors counts failures to write log messages so it can be reported
	// when writer start to work again. Needs to be accessed using atomics
	// to make race detector happy because it's read outside the mutex.
	errors int32
}

// Write writes out the given bytes, handling non-blocking sockets.
func (l *Writer) Write(data []byte) (int, error) {
	n := 0

	for n < len(data) {
		w, err := l.Next.Write(data[n:])
		n += w

		// Is it a non-blocking socket?
		if pathErr, ok := err.(*os.PathError); ok && pathErr.Timeout() {
			runtime.Gosched()
			continue
		}

		// Some other error?
		if err != nil {
			l.mu.Lock()
			atomic.AddInt32(&l.errors, 1)
			l.mu.Unlock()
			return n, err
		}
	}

	// Do we need to end with a '\n'?
	if len(data) == 0 || data[len(data)-1] != '\n' {
		l.Write([]byte{'\n'})
	}

	// Dirty read in case there were errors (rare).
	if atomic.LoadInt32(&l.errors) > 0 {
		l.mu.Lock()
		defer l.mu.Unlock()

		// Recheck condition under lock.
		if e := atomic.LoadInt32(&l.errors); e > 0 {
			msg := fmt.Sprintf("\n*** Dropped %d log messages ***\n", e)
			if _, err := l.Next.Write([]byte(msg)); err == nil {
				atomic.StoreInt32(&l.errors, 0)
			}
		}
	}

	return n, nil
}

// Emit emits the message.
func (l *Writer) Emit(_ int, _ Level, _ time.Time, format string, args ...interface{}) {
	fmt.Fprintf(l, format, args...)
}

// MultiEmitter is an emitter that emits to multiple Emitters.
type MultiEmitter []Emitter

// Emit emits to all emitters.
func (m *MultiEmitter) Emit(depth int, level Level, timestamp time.Time, format string, v ...interface{}) {
	for _, e := range *m {
		e.Emit(1+depth, level, timestamp, format, v...)
	}
}

// TestLogger is implemented by testing.T and testing.B.
type TestLogger interface {
	Logf(format string, v ...interface{})
}

// TestEmitter may be used for wrapping tests.
type TestEmitter struct {
	TestLogger
}

// Emit emits to the TestLogger.
func (t *TestEmitter) Emit(_ int, level Level, timestamp time.Time, format string, v ...interface{}) {
	t.Logf(format, v...)
}

// Logger is a high-level logging interface. It is in fact, not used within the
// log package. Rather it is provided for others to provide contextual loggers
// that may append some addition information to log statement. BasicLogger
// satisfies this interface, and may be passed around as a Logger.
type Logger interface {
	// Debugf logs a debug statement.
	Debugf(format string, v ...interface{})

	// Infof logs at an info level.
	Infof(format string, v ...interface{})

	// Warningf logs at a warning level.
	Warningf(format string, v ...interface{})

	// IsLogging returns true iff this level is being logged. This may be
	// used to short-circuit expensive operations for debugging calls.
	IsLogging(level Level) bool
}

// BasicLogger is the default implementation of Logger.
type BasicLogger struct {
	Level
	Emitter
}

// Debugf implements logger.Debugf.
func (l *BasicLogger) Debugf(format string, v ...interface{}) {
	l.DebugfAtDepth(1, format, v...)
}

// Infof implements logger.Infof.
func (l *BasicLogger) Infof(format string, v ...interface{}) {
	l.InfofAtDepth(1, format, v...)
}

// Warningf implements logger.Warningf.
func (l *BasicLogger) Warningf(format string, v ...interface{}) {
	l.WarningfAtDepth(1, format, v...)
}

// DebugfAtDepth logs at a specific depth.
func (l *BasicLogger) DebugfAtDepth(depth int, format string, v ...interface{}) {
	if l.IsLogging(Debug) {
		l.Emit(1+depth, Debug, time.Now(), format, v...)
	}
}

// InfofAtDepth logs at a specific depth.
func (l *BasicLogger) InfofAtDepth(depth int, format string, v ...interface{}) {
	if l.IsLogging(Info) {
		l.Emit(1+depth, Info, time.Now(), format, v...)
	}
}

// WarningfAtDepth logs at a specific depth.
func (l *BasicLogger) WarningfAtDepth(depth int, format string, v ...interface{}) {
	if l.IsLogging(Warning) {
		l.Emit(1+depth, Warning, time.Now(), format, v...)
	}
}

// IsLogging implements logger.IsLogging.
func (l *BasicLogger) IsLogging(level Level) bool {
	return atomic.LoadUint32((*uint32)(&l.Level)) >= uint32(level)
}

// SetLevel sets the logging level.
func (l *BasicLogger) SetLevel(level Level) {
	atomic.StoreUint32((*uint32)(&l.Level), uint32(level))
}

// logMu protects Log below. We use atomic operations to read the value, but
// updates require logMu to ensure consistency.
var logMu sync.Mutex

// log is the default logger.
var log atomic.Value

// Log retrieves the global logger.
func Log() *BasicLogger {
	return log.Load().(*BasicLogger)
}

// SetTarget sets the log target.
//
// This is not thread safe and shouldn't be called concurrently with any
// logging calls.
func SetTarget(target Emitter) {
	logMu.Lock()
	defer logMu.Unlock()
	oldLog := Log()
	log.Store(&BasicLogger{Level: oldLog.Level, Emitter: target})
}

// SetLevel sets the log level.
func SetLevel(newLevel Level) {
	Log().SetLevel(newLevel)
}

// Debugf logs to the global logger.
func Debugf(format string, v ...interface{}) {
	Log().DebugfAtDepth(1, format, v...)
}

// Infof logs to the global logger.
func Infof(format string, v ...interface{}) {
	Log().InfofAtDepth(1, format, v...)
}

// Warningf logs to the global logger.
func Warningf(format string, v ...interface{}) {
	Log().WarningfAtDepth(1, format, v...)
}

// DebugfAtDepth logs to the global logger.
func DebugfAtDepth(depth int, format string, v ...interface{}) {
	Log().DebugfAtDepth(1+depth, format, v...)
}

// InfofAtDepth logs to the global logger.
func InfofAtDepth(depth int, format string, v ...interface{}) {
	Log().InfofAtDepth(1+depth, format, v...)
}

// WarningfAtDepth logs to the global logger.
func WarningfAtDepth(depth int, format string, v ...interface{}) {
	Log().WarningfAtDepth(1+depth, format, v...)
}

// defaultStackSize is the default buffer size to allocate for stack traces.
const defaultStackSize = 1 << 16 // 64KB

// maxStackSize is the maximum buffer size to allocate for stack traces.
const maxStackSize = 1 << 26 // 64MB

// Stacks returns goroutine stacks, like panic.
func Stacks(all bool) []byte {
	var trace []byte
	for s := defaultStackSize; s <= maxStackSize; s *= 4 {
		trace = make([]byte, s)
		nbytes := runtime.Stack(trace, all)
		if nbytes == s {
			continue
		}
		return trace[:nbytes]
	}
	trace = append(trace, []byte("\n\n...<too large, truncated>")...)
	return trace
}

// Traceback logs the given message and dumps a stacktrace of the current
// goroutine.
//
// This will be print a traceback, tb, as Warningf(format+":\n%s", v..., tb).
func Traceback(format string, v ...interface{}) {
	v = append(v, Stacks(false))
	Warningf(format+":\n%s", v...)
}

// TracebackAll logs the given message and dumps a stacktrace of all goroutines.
//
// This will be print a traceback, tb, as Warningf(format+":\n%s", v..., tb).
func TracebackAll(format string, v ...interface{}) {
	v = append(v, Stacks(true))
	Warningf(format+":\n%s", v...)
}

// IsLogging returns whether the global logger is logging.
func IsLogging(level Level) bool {
	return Log().IsLogging(level)
}

// CopyStandardLogTo redirects the stdlib log package global output to the global
// logger for the specified level.
func CopyStandardLogTo(l Level) error {
	var f func(string, ...interface{})

	switch l {
	case Debug:
		f = Debugf
	case Info:
		f = Infof
	case Warning:
		f = Warningf
	default:
		return fmt.Errorf("unknown log level %v", l)
	}

	stdlog.SetOutput(linewriter.NewWriter(func(p []byte) {
		// We must not retain p, but log formatting is not required to
		// be synchronous (though the in-package implementations are),
		// so we must make a copy.
		b := make([]byte, len(p))
		copy(b, p)

		f("%s", b)
	}))

	return nil
}

func init() {
	// Store the initial value for the log.
	log.Store(&BasicLogger{Level: Info, Emitter: GoogleEmitter{&Writer{Next: os.Stderr}}})
}

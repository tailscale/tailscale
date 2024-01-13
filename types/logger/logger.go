// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package logger defines a type for writing to logs. It's just a
// convenience type so that we don't have to pass verbose func(...)
// types around.
package logger

import (
	"bufio"
	"bytes"
	"container/list"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"context"

	"tailscale.com/envknob"
	"tailscale.com/util/ctxkey"
)

// Logf is the basic Tailscale logger type: a printf-like func.
// Like log.Printf, the format need not end in a newline.
// Logf functions must be safe for concurrent use.
type Logf func(format string, args ...any)

// LogfKey stores and loads [Logf] values within a [context.Context].
var LogfKey = ctxkey.New("", Logf(log.Printf))

// A Context is a context.Context that should contain a custom log function, obtainable from FromContext.
// If no log function is present, FromContext will return log.Printf.
// To construct a Context, use Add
//
// Deprecated: Do not use.
type Context context.Context

// jenc is a json.Encode + bytes.Buffer pair wired up to be reused in a pool.
type jenc struct {
	buf bytes.Buffer
	enc *json.Encoder
}

var jencPool = &sync.Pool{New: func() any {
	je := new(jenc)
	je.enc = json.NewEncoder(&je.buf)
	return je
}}

// JSON marshals v as JSON and writes it to logf formatted with the annotation to make logtail
// treat it as a structured log.
//
// The recType is the record type and becomes the key of the wrapper
// JSON object that is logged. That is, if recType is "foo" and v is
// 123, the value logged is {"foo":123}.
//
// Do not use recType "logtail", "v", "text", or "metrics", with any case.
// Those are reserved for the logging system.
//
// The level can be from 0 to 9. Levels from 1 to 9 are included in
// the logged JSON object, like {"foo":123,"v":2}.
func (logf Logf) JSON(level int, recType string, v any) {
	je := jencPool.Get().(*jenc)
	defer jencPool.Put(je)
	je.buf.Reset()
	je.buf.WriteByte('{')
	je.enc.Encode(recType)
	je.buf.Truncate(je.buf.Len() - 1) // remove newline from prior Encode
	je.buf.WriteByte(':')
	if err := je.enc.Encode(v); err != nil {
		logf("[unexpected]: failed to encode structured JSON log record of type %q / %T: %v", recType, v, err)
		return
	}
	je.buf.Truncate(je.buf.Len() - 1) // remove newline from prior Encode
	je.buf.WriteByte('}')
	// Magic prefix recognized by logtail:
	logf("[v\x00JSON]%d%s", level%10, je.buf.Bytes())

}

// FromContext extracts a log function from ctx.
//
// Deprecated: Use [LogfKey.Value] instead.
func FromContext(ctx Context) Logf {
	return LogfKey.Value(ctx)
}

// Ctx constructs a Context from ctx with fn as its custom log function.
//
// Deprecated: Use [LogfKey.WithValue] instead.
func Ctx(ctx context.Context, fn Logf) Context {
	return LogfKey.WithValue(ctx, fn)
}

// WithPrefix wraps f, prefixing each format with the provided prefix.
func WithPrefix(f Logf, prefix string) Logf {
	return func(format string, args ...any) {
		f(prefix+format, args...)
	}
}

// FuncWriter returns an io.Writer that writes to f.
func FuncWriter(f Logf) io.Writer {
	return funcWriter{f}
}

// StdLogger returns a standard library logger from a Logf.
func StdLogger(f Logf) *log.Logger {
	return log.New(FuncWriter(f), "", 0)
}

type funcWriter struct{ f Logf }

func (w funcWriter) Write(p []byte) (int, error) {
	w.f("%s", p)
	return len(p), nil
}

// Discard is a Logf that throws away the logs given to it.
func Discard(string, ...any) {}

// limitData is used to keep track of each format string's associated
// rate-limiting data.
type limitData struct {
	bucket   *tokenBucket  // the token bucket associated with this string
	nBlocked int           // number of messages skipped
	ele      *list.Element // list element used to access this string in the cache
}

// rateFree are format string substrings that are exempt from rate limiting.
// Things should not be added to this unless they're already limited otherwise
// or are critical for generating important stats from the logs.
var rateFree = []string{
	"magicsock: disco: ",
	"magicsock: ParseEndpoint:",
	// grinder stats lines
	"SetPrefs: %v",
	"peer keys: %s",
	"v%v peers: %v",
	// debug messages printed by 'tailscale bugreport'
	"diag: ",
}

// RateLimitedFn is a wrapper for RateLimitedFnWithClock that includes the
// current time automatically. This is mainly for backward compatibility.
func RateLimitedFn(logf Logf, f time.Duration, burst int, maxCache int) Logf {
	return RateLimitedFnWithClock(logf, f, burst, maxCache, time.Now)
}

// RateLimitedFnWithClock returns a rate-limiting Logf wrapping the given
// logf. Messages are allowed through at a maximum of one message every f
// (where f is a time.Duration), in bursts of up to burst messages at a
// time. Up to maxCache format strings will be tracked separately.
// timeNow is a function that returns the current time, used for calculating
// rate limits.
func RateLimitedFnWithClock(logf Logf, f time.Duration, burst int, maxCache int, timeNow func() time.Time) Logf {
	if envknob.String("TS_DEBUG_LOG_RATE") == "all" {
		return logf
	}
	var (
		mu       sync.Mutex
		msgLim   = make(map[string]*limitData) // keyed by logf format
		msgCache = list.New()                  // a rudimentary LRU that limits the size of the map
	)

	return func(format string, args ...any) {
		// Shortcut for formats with no rate limit
		for _, sub := range rateFree {
			if strings.Contains(format, sub) {
				logf(format, args...)
				return
			}
		}

		mu.Lock()
		rl, ok := msgLim[format]
		if ok {
			msgCache.MoveToFront(rl.ele)
		} else {
			rl = &limitData{
				bucket: newTokenBucket(f, burst, timeNow()),
				ele:    msgCache.PushFront(format),
			}
			msgLim[format] = rl
			if msgCache.Len() > maxCache {
				delete(msgLim, msgCache.Back().Value.(string))
				msgCache.Remove(msgCache.Back())
			}
		}

		rl.bucket.AdvanceTo(timeNow())

		// Make sure there's enough room for at least a few
		// more logs before we unblock, so we don't alternate
		// between blocking and unblocking.
		if rl.nBlocked > 0 && rl.bucket.remaining >= 2 {
			// Only print this if we dropped more than 1
			// message. Otherwise we'd *increase* the total
			// number of log lines printed.
			if rl.nBlocked > 1 {
				logf("[RATELIMIT] format(%q) (%d dropped)",
					format, rl.nBlocked-1)
			}
			rl.nBlocked = 0
		}
		if rl.nBlocked == 0 && rl.bucket.Get() {
			hitLimit := rl.bucket.remaining == 0
			if hitLimit {
				// Enter "blocked" mode immediately after
				// reaching the burst limit. We want to
				// always accompany the format() message
				// with an example of the format, which is
				// effectively the same as printing the
				// message anyway. But this way they can
				// be on two separate lines and we don't
				// corrupt the original message.
				rl.nBlocked = 1
			}
			mu.Unlock() // release before calling logf
			logf(format, args...)
			if hitLimit {
				logf("[RATELIMIT] format(%q)", format)
			}
		} else {
			rl.nBlocked++
			mu.Unlock()
		}
	}
}

// SlowLoggerWithClock is a logger that applies rate limits similar to
// RateLimitedFnWithClock, but instead of dropping logs will sleep until they
// can be written. This should only be used for debug logs, and not in a hot path.
//
// The provided context, if canceled, will cause all logs to be dropped and
// prevent any sleeps.
func SlowLoggerWithClock(ctx context.Context, logf Logf, f time.Duration, burst int, timeNow func() time.Time) Logf {
	var (
		mu sync.Mutex
		tb = newTokenBucket(f, burst, timeNow())
	)
	return func(format string, args ...any) {
		if ctx.Err() != nil {
			return
		}

		// Hold the mutex for the entire length of the check + log
		// since our token bucket isn't concurrency-safe.
		mu.Lock()
		defer mu.Unlock()

		tb.AdvanceTo(timeNow())

		// If we can get a token, then do that and return.
		if tb.Get() {
			logf(format, args...)
			return
		}

		// Otherwise, sleep for 2x the duration so that we don't
		// immediately sleep again on the next call.
		tmr := time.NewTimer(2 * f)
		defer tmr.Stop()
		select {
		case curr := <-tmr.C:
			tb.AdvanceTo(curr)
		case <-ctx.Done():
			return
		}
		if !tb.Get() {
			log.Printf("[unexpected] error rate-limiting in SlowLoggerWithClock")
			return
		}
		logf(format, args...)
	}
}

// LogOnChange logs a given line only if line != lastLine, or if maxInterval has passed
// since the last time this identical line was logged.
func LogOnChange(logf Logf, maxInterval time.Duration, timeNow func() time.Time) Logf {
	var (
		mu          sync.Mutex
		sLastLogged string
		tLastLogged = timeNow()
	)

	return func(format string, args ...any) {
		s := fmt.Sprintf(format, args...)

		mu.Lock()
		if s == sLastLogged && timeNow().Sub(tLastLogged) < maxInterval {
			mu.Unlock()
			return
		}
		sLastLogged = s
		tLastLogged = timeNow()
		mu.Unlock()

		// Re-stringify it (instead of using "%s", s) so something like "%s"
		// doesn't end up getting rate-limited. (And can't use 's' as the pattern,
		// as it might contain formatting directives.)
		logf(format, args...)
	}
}

// ArgWriter is a fmt.Formatter that can be passed to any Logf func to
// efficiently write to a %v argument without allocations.
type ArgWriter func(*bufio.Writer)

func (fn ArgWriter) Format(f fmt.State, _ rune) {
	bw := argBufioPool.Get().(*bufio.Writer)
	bw.Reset(f)
	fn(bw)
	bw.Flush()
	argBufioPool.Put(bw)
}

var argBufioPool = &sync.Pool{New: func() any { return bufio.NewWriterSize(io.Discard, 1024) }}

// Filtered returns a Logf that silently swallows some log lines.
// Each inbound format and args is evaluated and printed to a string s.
// The original format and args are passed to logf if and only if allow(s) returns true.
func Filtered(logf Logf, allow func(s string) bool) Logf {
	return func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if !allow(msg) {
			return
		}
		logf(format, args...)
	}
}

// LogfCloser wraps logf to create a logger that can be closed.
// Calling close makes all future calls to newLogf into no-ops.
func LogfCloser(logf Logf) (newLogf Logf, close func()) {
	var (
		mu     sync.Mutex
		closed bool
	)
	close = func() {
		mu.Lock()
		defer mu.Unlock()
		closed = true
	}
	newLogf = func(msg string, args ...any) {
		mu.Lock()
		if closed {
			mu.Unlock()
			return
		}
		mu.Unlock()
		logf(msg, args...)
	}
	return newLogf, close
}

// AsJSON returns a formatter that formats v as JSON. The value is suitable to
// passing to a regular %v printf argument. (%s is not required)
//
// If json.Marshal returns an error, the output is "%%!JSON-ERROR:" followed by
// the error string.
func AsJSON(v any) fmt.Formatter {
	return asJSONResult{v}
}

type asJSONResult struct{ v any }

func (a asJSONResult) Format(s fmt.State, verb rune) {
	v, err := json.Marshal(a.v)
	if err != nil {
		fmt.Fprintf(s, "%%!JSON-ERROR:%v", err)
		return
	}
	s.Write(v)
}

// TBLogger is the testing.TB subset needed by TestLogger.
type TBLogger interface {
	Helper()
	Logf(format string, args ...any)
}

// TestLogger returns a logger that logs to tb.Logf
// with a prefix to make it easier to distinguish spam
// from explicit test failures.
func TestLogger(tb TBLogger) Logf {
	return func(format string, args ...any) {
		tb.Helper()
		tb.Logf("    ... "+format, args...)
	}
}

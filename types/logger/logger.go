// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package logger defines a type for writing to logs. It's just a
// convenience type so that we don't have to pass verbose func(...)
// types around.
package logger

import (
	"bufio"
	"container/list"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Logf is the basic Tailscale logger type: a printf-like func.
// Like log.Printf, the format need not end in a newline.
// Logf functions must be safe for concurrent use.
type Logf func(format string, args ...interface{})

// WithPrefix wraps f, prefixing each format with the provided prefix.
func WithPrefix(f Logf, prefix string) Logf {
	return func(format string, args ...interface{}) {
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
func Discard(string, ...interface{}) {}

// limitData is used to keep track of each format string's associated
// rate-limiting data.
type limitData struct {
	bucket   *tokenBucket  // the token bucket associated with this string
	nBlocked int           // number of messages skipped
	ele      *list.Element // list element used to access this string in the cache
}

var disableRateLimit = os.Getenv("TS_DEBUG_LOG_RATE") == "all"

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
	if disableRateLimit {
		return logf
	}
	var (
		mu       sync.Mutex
		msgLim   = make(map[string]*limitData) // keyed by logf format
		msgCache = list.New()                  // a rudimentary LRU that limits the size of the map
	)

	return func(format string, args ...interface{}) {
		// Shortcut for formats with no rate limit
		for _, sub := range rateFree {
			if strings.Contains(format, sub) {
				logf(format, args...)
				return
			}
		}

		mu.Lock()
		defer mu.Unlock()
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
			logf(format, args...)
			if rl.bucket.remaining == 0 {
				// Enter "blocked" mode immediately after
				// reaching the burst limit. We want to
				// always accompany the format() message
				// with an example of the format, which is
				// effectively the same as printing the
				// message anyway. But this way they can
				// be on two separate lines and we don't
				// corrupt the original message.
				logf("[RATELIMIT] format(%q)", format)
				rl.nBlocked = 1
			}
			return
		} else {
			rl.nBlocked++
		}
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

	return func(format string, args ...interface{}) {
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

var argBufioPool = &sync.Pool{New: func() interface{} { return bufio.NewWriterSize(ioutil.Discard, 1024) }}

// Filtered returns a Logf that silently swallows some log lines.
// Each inbound format and args is evaluated and printed to a string s.
// The original format and args are passed to logf if and only if allow(s) returns true.
func Filtered(logf Logf, allow func(s string) bool) Logf {
	return func(format string, args ...interface{}) {
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
	newLogf = func(msg string, args ...interface{}) {
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

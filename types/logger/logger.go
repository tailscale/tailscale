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

	"golang.org/x/time/rate"
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
	lim        *rate.Limiter // the token bucket associated with this string
	msgBlocked bool          // whether a "duplicate error" message has already been logged
	ele        *list.Element // list element used to access this string in the cache
}

var disableRateLimit = os.Getenv("TS_DEBUG_LOG_RATE") == "all"

// rateFreePrefix are format string prefixes that are exempt from rate limiting.
// Things should not be added to this unless they're already limited otherwise.
var rateFreePrefix = []string{
	"magicsock: disco: ",
	"magicsock: CreateEndpoint:",
}

// RateLimitedFn returns a rate-limiting Logf wrapping the given logf.
// Messages are allowed through at a maximum of one message every f (where f is a time.Duration), in
// bursts of up to burst messages at a time. Up to maxCache strings will be held at a time.
func RateLimitedFn(logf Logf, f time.Duration, burst int, maxCache int) Logf {
	if disableRateLimit {
		return logf
	}
	r := rate.Every(f)
	var (
		mu       sync.Mutex
		msgLim   = make(map[string]*limitData) // keyed by logf format
		msgCache = list.New()                  // a rudimentary LRU that limits the size of the map
	)

	type verdict int
	const (
		allow verdict = iota
		warn
		block
	)

	judge := func(format string) verdict {
		for _, pfx := range rateFreePrefix {
			if strings.HasPrefix(format, pfx) {
				return allow
			}
		}

		mu.Lock()
		defer mu.Unlock()
		rl, ok := msgLim[format]
		if ok {
			msgCache.MoveToFront(rl.ele)
		} else {
			rl = &limitData{
				lim: rate.NewLimiter(r, burst),
				ele: msgCache.PushFront(format),
			}
			msgLim[format] = rl
			if msgCache.Len() > maxCache {
				delete(msgLim, msgCache.Back().Value.(string))
				msgCache.Remove(msgCache.Back())
			}
		}
		if rl.lim.Allow() {
			rl.msgBlocked = false
			return allow
		}
		if !rl.msgBlocked {
			rl.msgBlocked = true
			return warn
		}
		return block
	}

	return func(format string, args ...interface{}) {
		switch judge(format) {
		case allow:
			logf(format, args...)
		case warn:
			// For the warning, log the specific format string
			logf("[RATE LIMITED] format string \"%s\"", format)
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

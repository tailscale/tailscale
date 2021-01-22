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
//
// Functions that wrap logger functions must pass through the original
// format and args, possibly augmented.
// Replacing the format and args (e.g. with fmt.Sprintf and %s)
// disrupts rate limiting and other package logger internals.
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
// StdLoggers are discouraged, because they flatten all logging formats into %s.
// This interacts badly with rate limiting.
// To ensure that StdLoggers do not interfere with each other,
// he log function passed to StdLogger should be wrapped in a RateLimitContext.
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

	// judge decides the fate of a log request and returns the string that should be used
	// to describe the format when the verdict is warn.
	judge := func(format string, args ...interface{}) (v verdict, warnFormat string) {
		contexts := make([]string, 0, 4) // make room for a couple of contexts
		for _, arg := range args {
			switch arg := arg.(type) {
			case noRateLimit:
				return allow, ""
			case rateLimitContext:
				contexts = append(contexts, arg.context)
			}
		}

		for _, pfx := range rateFreePrefix {
			if strings.HasPrefix(format, pfx) {
				return allow, ""
			}
		}

		if len(contexts) > 0 {
			format += " (rate-limit-context:" + strings.Join(contexts, ",") + ")"
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
			return allow, ""
		}
		if !rl.msgBlocked {
			rl.msgBlocked = true
			format = noopFormatRemover.Replace(format)
			return warn, format
		}
		return block, ""
	}

	return func(format string, args ...interface{}) {
		switch v, warnFormat := judge(format, args...); v {
		case allow:
			logf(format, args...)
		case warn:
			// For the warning, log the specific format string
			logf("[RATE LIMITED] format string \"%s\" (example: \"%s\")", warnFormat, strings.TrimSpace(fmt.Sprintf(format, args...)))
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

// noopFormat is a special format we use to indicate that the corresponding
// argument is an internal implementation detail and can be ignored.
// It is selected specifically to be unusual, in the hopes in never occurs anywhere else.
const noopFormat = "%+5.2L"

var noopFormatRemover = strings.NewReplacer(noopFormat, "")

// noopFormatter is a type that generates nothing when printing using fmt.Sprintf.
// It may be embedded in types for internal-use args, so that, which used
// in correspondence with noopFormat, they have no impact on the actual log output.
type noopFormatter struct{}

func (noopFormatter) Format(fmt.State, rune) {}

func logfWithExtra(logf Logf, extra interface{}) Logf {
	return func(format string, args ...interface{}) {
		args = args[:len(args):len(args)]
		args = append(args, extra)
		logf(format+noopFormat, args...)
	}
}

// NoRateLimit removes rate limiting for logf.
func NoRateLimit(logf Logf) Logf {
	return logfWithExtra(logf, noRateLimit{})
}

// noRateLimit is a sentinel type.
// If there are any arguments of type noRateLimit in a call
// to a rate-limiter created by RateLimitedFn, then the
// rate-limiter ignores that log call.
type noRateLimit struct {
	noopFormatter
}

// RateLimitContext adds extra rate limiter context beyond the format string.
func RateLimitContext(logf Logf, context string) Logf {
	return logfWithExtra(logf, rateLimitContext{context: context})
}

type rateLimitContext struct {
	noopFormatter
	context string
}

// ApplyPostProcess works with PostProcess to allow
// loggers to do processing of the fully-formatted log string.
// PostProcess asks for post-processing to be done;
// ApplyPostProcess actually does the work.
//
// Typical usage is:
//   * start with logf
//   * logf = ApplyPostProcess(logf)
//   * logf = RateLimitedFn(logf, ...)
//   * logf = PostProcess(logf, postProcessor)
//
// This allows the existing format string to be preserved
// as it passes through the rate-limiter.
// Then ApplyPostProcess does the processing defined by
// postProcessor and passes the final string to the initial logf.
func ApplyPostProcess(logf Logf) Logf {
	return func(format string, args ...interface{}) {
		var fns []func(string) string
		for _, arg := range args {
			if pp, ok := arg.(postProcess); ok {
				fns = append(fns, pp.fn)
			}
		}
		if len(fns) > 0 {
			orig := fmt.Sprintf(format, args...)
			s := orig
			// Apply in LIFO order.
			for i := len(fns) - 1; i >= 0; i-- {
				s = fns[i](s)
			}
			if s != orig {
				logf("%s", s)
				return
			}
		}
		logf(format, args...)
	}
}

// PostProcess requests that fully formatted logs be rewritten using fn.
// In order to take effect, logf must have been wrapped at some point
// using AllowPostProcessing.
func PostProcess(logf Logf, fn func(string) string) Logf {
	return logfWithExtra(logf, postProcess{fn: fn})
}

type postProcess struct {
	noopFormatter
	fn func(string) string
}

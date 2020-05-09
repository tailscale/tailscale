// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package logger defines a type for writing to logs. It's just a
// convenience type so that we don't have to pass verbose func(...)
// types around.
package logger

import (
	"container/list"
	"fmt"
	"io"
	"log"
	"sync"

	"golang.org/x/time/rate"
)

// Logf is the basic Tailscale logger type: a printf-like func.
// Like log.Printf, the format need not end in a newline.
// Logf functions should be safe for concurrent use.
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

// RateLimitedFn implements rate limiting by fstring on a given Logf.
// Messages are allowed through at a maximum of f messages/second, in
// bursts of up to b messages at a time. Up to m strings will be held at a time.
func RateLimitedFn(logf Logf, f float64, b int, m int) Logf {
	r := rate.Limit(f)
	msgLim := make(map[string]*limitData)
	msgCache := list.New() // a rudimentary LRU that limits the size of the map
	mu := &sync.Mutex{}

	return func(format string, args ...interface{}) {
		mu.Lock()
		rl, ok := msgLim[format]
		if ok {
			msgCache.MoveToFront(rl.ele)
			if rl.lim.Allow() {
				rl.msgBlocked = false
				mu.Unlock()
				logf(format, args...)
			} else {
				if !rl.msgBlocked {
					rl.msgBlocked = true
					mu.Unlock()
					logf("Repeated messages were suppressed by rate limiting. Original message: %s",
						fmt.Sprintf(format, args...))
				} else {
					mu.Unlock()
				}
			}
		} else {
			msgLim[format] = &limitData{rate.NewLimiter(r, b), false, msgCache.PushFront(format)}
			msgLim[format].lim.Allow()
			mu.Unlock()
			logf(format, args...)
		}

		mu.Lock()
		if msgCache.Len() > m {
			delete(msgLim, msgCache.Back().Value.(string))
			msgCache.Remove(msgCache.Back())
		}
		mu.Unlock()
	}
}

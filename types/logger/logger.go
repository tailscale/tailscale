// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package logger defines a type for writing to logs. It's just a
// convenience type so that we don't have to pass verbose func(...)
// types around.
package logger

import (
	"fmt"
	"io"
	"log"
	"time"

	"golang.org/x/time/rate"
)

// Logf is the basic Tailscale logger type: a printf-like func.
// Like log.Printf, the format need not end in a newline.
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

type limitData struct {
	lim          *rate.Limiter
	lastAccessed time.Time
	msgBlocked   bool
}

// RateLimitedFn implements rate limiting by fstring on a given Logf.
// Messages are allowed through at a maximum of r messages/second, in
// bursts of up to b messages at a time.
func RateLimitedFn(logf Logf, f float64, b int) Logf {
	r := rate.Limit(f)
	msgList := make(map[string]limitData)
	lastPurge := time.Now()

	rlLogf := func(s string, args ...interface{}) {
		if rl, ok := msgList[s]; ok {

			// Fields of structs contained in maps can't be modified; this is
			// the workaround. See issue https://github.com/golang/go/issues/3117
			temp := msgList[s]
			temp.lastAccessed = time.Now()
			msgList[s] = temp

			if rl.lim.Allow() {
				rl.msgBlocked = false
				logf(s, args)
			} else {
				if !rl.msgBlocked {
					temp = msgList[s]
					temp.msgBlocked = true
					msgList[s] = temp
					logf("Repeated messages were suppressed by rate limiting. Original message: " +
						fmt.Sprintf(s, args))
				}
			}
		} else {
			msgList[s] = limitData{rate.NewLimiter(r, b), time.Now(), false}
			msgList[s].lim.Allow()
			logf(s, args)
		}

		// Purge msgList of outdated keys to reduce overhead. Must be done by copying
		// over to a new map, since deleting in maps is done through a zombie flag
		if time.Since(lastPurge) >= time.Minute {
			newList := make(map[string]limitData)
			for k, v := range msgList {
				if time.Since(v.lastAccessed) < 5*time.Second {
					newList[k] = v
				}
			}
			msgList = nil
			msgList = newList
		}
	}

	return rlLogf
}

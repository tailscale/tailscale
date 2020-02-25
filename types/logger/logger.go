// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package logger defines a type for writing to logs. It's just a
// convenience type so that we don't have to pass verbose func(...)
// types around.
package logger

// Logf is the basic Tailscale logger type: a printf-like func.
type Logf func(format string, args ...interface{})

// WithPrefix wraps f, prefixing each format with the provided prefix.
func WithPrefix(f Logf, prefix string) Logf {
	return func(format string, args ...interface{}) {
		f(prefix+format, args...)
	}
}

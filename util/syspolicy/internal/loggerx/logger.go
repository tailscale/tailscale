// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package loggerx provides logging functions to the rest of the syspolicy packages.
package loggerx

import (
	"log"

	"tailscale.com/types/lazy"
	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/internal"
)

const (
	errorPrefix   = "syspolicy: "
	verbosePrefix = "syspolicy: [v2] "
)

var (
	lazyErrorf   lazy.SyncValue[logger.Logf]
	lazyVerbosef lazy.SyncValue[logger.Logf]
)

// Errorf formats and writes an error message to the log.
func Errorf(format string, args ...any) {
	errorf := lazyErrorf.Get(func() logger.Logf {
		return logger.WithPrefix(log.Printf, errorPrefix)
	})
	errorf(format, args...)
}

// Verbosef formats and writes an optional, verbose message to the log.
func Verbosef(format string, args ...any) {
	verbosef := lazyVerbosef.Get(func() logger.Logf {
		return logger.WithPrefix(log.Printf, verbosePrefix)
	})
	verbosef(format, args...)
}

// SetForTest sets the specified errorf and verbosef functions for the duration
// of tb and its subtests.
func SetForTest(tb internal.TB, errorf, verbosef logger.Logf) {
	lazyErrorf.SetForTest(tb, errorf, nil)
	lazyVerbosef.SetForTest(tb, verbosef, nil)
}

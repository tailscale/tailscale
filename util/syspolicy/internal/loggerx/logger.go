// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package loggerx provides logging functions to the rest of the syspolicy packages.
package loggerx

import (
	"log"
	"sync/atomic"

	"tailscale.com/types/lazy"
	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/internal"
)

const (
	normalPrefix  = "syspolicy: "
	verbosePrefix = "syspolicy: [v2] "
)

var (
	debugLogging atomic.Bool // whether debugging logging is enabled

	lazyPrintf   lazy.SyncValue[logger.Logf]
	lazyVerbosef lazy.SyncValue[logger.Logf]
)

// SetDebugLoggingEnabled controls whether spammy debug logging is enabled.
func SetDebugLoggingEnabled(v bool) {
	debugLogging.Store(v)
}

// Errorf formats and writes an error message to the log.
func Errorf(format string, args ...any) {
	printf(format, args...)
}

// Verbosef formats and writes an optional, verbose message to the log.
func Verbosef(format string, args ...any) {
	if debugLogging.Load() {
		printf(format, args...)
	} else {
		verbosef(format, args...)
	}
}

func printf(format string, args ...any) {
	lazyPrintf.Get(func() logger.Logf {
		return logger.WithPrefix(log.Printf, normalPrefix)
	})(format, args...)
}

func verbosef(format string, args ...any) {
	lazyVerbosef.Get(func() logger.Logf {
		return logger.WithPrefix(log.Printf, verbosePrefix)
	})(format, args...)
}

// SetForTest sets the specified printf and verbosef functions for the duration
// of tb and its subtests.
func SetForTest(tb internal.TB, printf, verbosef logger.Logf) {
	lazyPrintf.SetForTest(tb, printf, nil)
	lazyVerbosef.SetForTest(tb, verbosef, nil)
}

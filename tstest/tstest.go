// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tstest provides utilities for use in unit tests.
package tstest

import (
	"context"
	"testing"
	"time"

	"tailscale.com/logtail/backoff"
	"tailscale.com/types/logger"
)

// Replace replaces the value of target with val.
// The old value is restored when the test ends.
func Replace[T any](t testing.TB, target *T, val T) {
	t.Helper()
	if target == nil {
		t.Fatalf("Replace: nil pointer")
		panic("unreachable") // pacify staticcheck
	}
	old := *target
	t.Cleanup(func() {
		*target = old
	})

	*target = val
	return
}

// WaitFor retries try for up to maxWait.
// It returns nil once try returns nil the first time.
// If maxWait passes without success, it returns try's last error.
func WaitFor(maxWait time.Duration, try func() error) error {
	bo := backoff.NewBackoff("wait-for", logger.Discard, maxWait/4)
	deadline := time.Now().Add(maxWait)
	var err error
	for time.Now().Before(deadline) {
		err = try()
		if err == nil {
			break
		}
		bo.BackOff(context.Background(), err)
	}
	return err
}

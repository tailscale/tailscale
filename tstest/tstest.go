// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tstest provides utilities for use in unit tests.
package tstest

import (
	"context"
	"math/rand"
	"os"
	"strconv"
	"sync"
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

var (
	seed     int64
	seedOnce sync.Once
)

// GetSeed gets the current global random test seed, by default this is based on
// the current time, but can be fixed to a particular value using the
// TS_TEST_SEED environment variable.
func GetSeed(t testing.TB) int64 {
	t.Helper()

	seedOnce.Do(func() {
		if s := os.Getenv("TS_TEST_SEED"); s != "" {
			var err error
			seed, err = strconv.ParseInt(s, 10, 64)
			if err != nil {
				t.Fatalf("invalid TS_TEST_SEED: %v", err)
			}
		} else {
			seed = time.Now().UnixNano()
		}
	})
	return seed
}

// SeedRand seeds the standard library global rand with the current test seed.
func SeedRand(t testing.TB) {
	t.Helper()

	// Seed is called every time, as other tests may execute code that reseeds
	// the global rand.
	rand.Seed(GetSeed(t))
	t.Logf("TS_TEST_SEED=%d", seed)
}

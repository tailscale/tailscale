// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tstest provides utilities for use in unit tests.
package tstest

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/types/logger"
	"tailscale.com/util/backoff"
	"tailscale.com/util/cibuild"
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

var testNum atomic.Int32

// Shard skips t if it's not running if the TS_TEST_SHARD test shard is set to
// "n/m" and this test execution number in the process mod m is not equal to n-1.
// That is, to run with 4 shards, set TS_TEST_SHARD=1/4, ..., TS_TEST_SHARD=4/4
// for the four jobs.
func Shard(t testing.TB) {
	e := os.Getenv("TS_TEST_SHARD")
	a, b, ok := strings.Cut(e, "/")
	if !ok {
		return
	}
	wantShard, _ := strconv.ParseInt(a, 10, 32)
	shards, _ := strconv.ParseInt(b, 10, 32)
	if wantShard == 0 || shards == 0 {
		return
	}

	shard := ((testNum.Add(1) - 1) % int32(shards)) + 1
	if shard != int32(wantShard) {
		t.Skipf("skipping shard %d/%d (process has TS_TEST_SHARD=%q)", shard, shards, e)
	}
}

// SkipOnUnshardedCI skips t if we're in CI and the TS_TEST_SHARD
// environment variable isn't set.
func SkipOnUnshardedCI(t testing.TB) {
	if cibuild.On() && os.Getenv("TS_TEST_SHARD") == "" {
		t.Skip("skipping on CI without TS_TEST_SHARD")
	}
}

var serializeParallel = envknob.RegisterBool("TS_SERIAL_TESTS")

// Parallel calls t.Parallel, unless TS_SERIAL_TESTS is set true.
func Parallel(t *testing.T) {
	if !serializeParallel() {
		t.Parallel()
	}
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package execqueue

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestExecQueue(t *testing.T) {
	ctx := context.Background()
	var n atomic.Int32
	q := &ExecQueue{}
	defer q.Shutdown()
	q.Add(func() { n.Add(1) })
	q.Wait(ctx)
	if got := n.Load(); got != 1 {
		t.Errorf("n=%d; want 1", got)
	}
}

// Test that RunSync doesn't hold q.mu and block Shutdown
// as we saw in tailscale/tailscale#18502
func TestExecQueueRunSyncLocking(t *testing.T) {
	q := &ExecQueue{}
	q.RunSync(t.Context(), func() {
		q.Shutdown()
	})
}

func TestShutdownAndWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := &ExecQueue{}
		started := make(chan struct{})
		release := make(chan struct{})
		var finished, ranPending atomic.Bool
		q.Add(func() {
			close(started)
			<-release
			finished.Store(true)
		})
		q.Add(func() { ranPending.Store(true) })
		<-started

		// The fake clock only advances once ShutdownAndWait below is
		// blocked, so the release cannot fire early.
		go func() {
			time.Sleep(time.Second)
			close(release)
		}()
		if err := q.ShutdownAndWait(context.Background()); err != nil {
			t.Fatalf("ShutdownAndWait: %v", err)
		}
		if !finished.Load() {
			t.Error("ShutdownAndWait returned before the in-flight function completed")
		}
		if ranPending.Load() {
			t.Error("pending function ran after shutdown")
		}
	})
}

func TestShutdownAndWaitTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := &ExecQueue{}
		started := make(chan struct{})
		release := make(chan struct{})
		q.Add(func() {
			close(started)
			<-release
		})
		<-started

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := q.ShutdownAndWait(ctx); err == nil {
			t.Error("ShutdownAndWait = nil; want deadline exceeded")
		}
		close(release)
	})
}

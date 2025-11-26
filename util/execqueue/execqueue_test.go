// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package execqueue

import (
	"context"
	"sync/atomic"
	"testing"
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

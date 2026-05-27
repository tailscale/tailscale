// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// errProjectionTimeout is returned by waitForBlueprintProjection when
// the deadline passes without the daemon reporting a matching
// projection. The caller treats this as success-of-binding +
// failure-of-display: the underlying join itself is unaffected.
var errProjectionTimeout = errors.New("blueprint projection not received before deadline")

// waitForBlueprintProjection polls fetch every interval until the
// daemon reports the node is Running with Self.BlueprintID == wantID
// and Self.BlueprintConfig != nil, or until timeout elapses, or until
// ctx is canceled.
//
// fetch errors are treated as transient: the function keeps polling
// until success or timeout. ctx cancellation propagates out
// immediately.
//
// This function exists separate from runJoin so the wait-loop
// behavior can be tested without a fake LocalClient.
func waitForBlueprintProjection(ctx context.Context, fetch func(context.Context) (*ipnstate.Status, error), wantID string, interval, timeout time.Duration) (*tailcfg.BlueprintConfig, error) {
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		st, err := fetch(ctx)
		if err == nil && st != nil && st.BackendState == ipn.Running.String() &&
			st.Self != nil && st.Self.BlueprintID == wantID && st.Self.BlueprintConfig != nil {
			return st.Self.BlueprintConfig, nil
		}
		if time.Now().After(deadline) {
			return nil, errProjectionTimeout
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
		}
	}
}

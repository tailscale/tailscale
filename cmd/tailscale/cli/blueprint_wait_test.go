// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

func TestWaitForBlueprintProjection_Success(t *testing.T) {
	calls := 0
	want := &tailcfg.BlueprintConfig{Tags: []string{"tag:bp//foo"}}
	fetch := func(ctx context.Context) (*ipnstate.Status, error) {
		calls++
		if calls < 3 {
			return &ipnstate.Status{
				BackendState: ipn.Starting.String(),
				Self:         &ipnstate.PeerStatus{},
			}, nil
		}
		return &ipnstate.Status{
			BackendState: ipn.Running.String(),
			Self: &ipnstate.PeerStatus{
				BlueprintID:     "foo",
				BlueprintConfig: want,
			},
		}, nil
	}

	got, err := waitForBlueprintProjection(context.Background(), fetch, "foo", 1*time.Millisecond, 1*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("returned cfg = %p; want %p", got, want)
	}
	if calls < 3 {
		t.Errorf("expected at least 3 fetch calls; got %d", calls)
	}
}

func TestWaitForBlueprintProjection_Timeout(t *testing.T) {
	fetch := func(ctx context.Context) (*ipnstate.Status, error) {
		// Never advances past Starting.
		return &ipnstate.Status{
			BackendState: ipn.Starting.String(),
			Self:         &ipnstate.PeerStatus{},
		}, nil
	}
	_, err := waitForBlueprintProjection(context.Background(), fetch, "foo", 1*time.Millisecond, 10*time.Millisecond)
	if !errors.Is(err, errProjectionTimeout) {
		t.Errorf("err = %v; want errProjectionTimeout", err)
	}
}

func TestWaitForBlueprintProjection_MismatchedID(t *testing.T) {
	// Status is Running with a projection, but for a DIFFERENT blueprint
	// (stale netmap during a re-join). The helper must keep polling.
	calls := 0
	fetch := func(ctx context.Context) (*ipnstate.Status, error) {
		calls++
		return &ipnstate.Status{
			BackendState: ipn.Running.String(),
			Self: &ipnstate.PeerStatus{
				BlueprintID:     "stale",
				BlueprintConfig: &tailcfg.BlueprintConfig{},
			},
		}, nil
	}
	_, err := waitForBlueprintProjection(context.Background(), fetch, "fresh", 1*time.Millisecond, 5*time.Millisecond)
	if !errors.Is(err, errProjectionTimeout) {
		t.Errorf("err = %v; want errProjectionTimeout (mismatched id should not declare success)", err)
	}
	if calls < 2 {
		t.Errorf("expected multiple polls; got %d", calls)
	}
}

func TestWaitForBlueprintProjection_FetchError(t *testing.T) {
	// A status fetch error mid-loop is transient; keep polling until timeout.
	calls := 0
	fetch := func(ctx context.Context) (*ipnstate.Status, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("daemon not ready")
		}
		return &ipnstate.Status{
			BackendState: ipn.Running.String(),
			Self: &ipnstate.PeerStatus{
				BlueprintID:     "foo",
				BlueprintConfig: &tailcfg.BlueprintConfig{},
			},
		}, nil
	}
	cfg, err := waitForBlueprintProjection(context.Background(), fetch, "foo", 1*time.Millisecond, 1*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Error("cfg = nil; want non-nil")
	}
}

func TestWaitForBlueprintProjection_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fetch := func(ctx context.Context) (*ipnstate.Status, error) {
		return &ipnstate.Status{BackendState: ipn.Starting.String(), Self: &ipnstate.PeerStatus{}}, nil
	}
	_, err := waitForBlueprintProjection(ctx, fetch, "foo", 1*time.Millisecond, 1*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled", err)
	}
}

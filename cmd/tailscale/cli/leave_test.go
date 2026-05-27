// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"strings"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

func TestRenderLeaveMessage_Bound(t *testing.T) {
	cfg := &tailcfg.BlueprintConfig{
		Tags:      []string{"tag:bp//foo"},
		ServeApps: []string{"app:github"},
	}
	var sb strings.Builder
	renderLeaveMessage(&sb, "foo", cfg)
	out := sb.String()
	if !strings.Contains(out, "Detached from blueprint bp:foo") {
		t.Errorf("missing detach line; got:\n%s", out)
	}
	if !strings.Contains(out, "Released:") {
		t.Errorf("missing 'Released:' header; got:\n%s", out)
	}
	if !strings.Contains(out, "Tags:      tag:bp//foo") {
		t.Errorf("missing projection content; got:\n%s", out)
	}
}

func TestRenderLeaveMessage_BoundNilProjection(t *testing.T) {
	var sb strings.Builder
	renderLeaveMessage(&sb, "foo", nil)
	out := sb.String()
	if out != "Detached from blueprint bp:foo and logged out.\n" {
		t.Errorf("unexpected output:\n%q", out)
	}
}

func TestRenderLeaveMessage_NotBound(t *testing.T) {
	var sb strings.Builder
	renderLeaveMessage(&sb, "", nil)
	out := sb.String()
	if out != "Logged out. (Node was not blueprint-bound.)\n" {
		t.Errorf("unexpected output:\n%q", out)
	}
}

// Helper accessor for the status-snapshot extraction logic used by
// runLeave. Verifies it pulls BlueprintConfig from Self when present.
func TestSnapshotProjectionFromStatus(t *testing.T) {
	want := &tailcfg.BlueprintConfig{Tags: []string{"x"}}
	st := &ipnstate.Status{
		Self: &ipnstate.PeerStatus{
			BlueprintID:     "foo",
			BlueprintConfig: want,
		},
	}
	got := snapshotProjection(st)
	if got != want {
		t.Errorf("snapshotProjection = %p; want %p", got, want)
	}

	if snapshotProjection(nil) != nil {
		t.Error("nil status should return nil")
	}
	if snapshotProjection(&ipnstate.Status{}) != nil {
		t.Error("status with nil Self should return nil")
	}
}

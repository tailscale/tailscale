// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// TestPeerStatusFromNodeCopiesBlueprintID verifies that peerStatusFromNode
// copies tailcfg.Node.BlueprintID into PeerStatus.BlueprintID. The same
// helper feeds both peer iteration (populatePeerStatusLocked) and the
// self-status mutator, so a single positive test covers both call sites.
func TestPeerStatusFromNodeCopiesBlueprintID(t *testing.T) {
	n := (&tailcfg.Node{
		ID:          1,
		StableID:    "stable-1",
		BlueprintID: "github-connector",
	}).View()
	var ps ipnstate.PeerStatus
	peerStatusFromNode(&ps, n)
	if ps.BlueprintID != "github-connector" {
		t.Errorf("BlueprintID = %q; want %q", ps.BlueprintID, "github-connector")
	}
}

// TestPeerStatusFromNodeEmptyBlueprintID verifies the non-bound case.
func TestPeerStatusFromNodeEmptyBlueprintID(t *testing.T) {
	n := (&tailcfg.Node{ID: 1, StableID: "stable-1"}).View()
	var ps ipnstate.PeerStatus
	peerStatusFromNode(&ps, n)
	if ps.BlueprintID != "" {
		t.Errorf("BlueprintID = %q; want empty", ps.BlueprintID)
	}
}

// TestPeerStatusFromNodeDoesNotCopyBlueprintConfig confirms peer entries
// never carry a BlueprintConfig: it's a Self-only field. The wire field
// is on tailcfg.Node so the server could in principle send it for any
// node; the local helper must filter regardless.
func TestPeerStatusFromNodeDoesNotCopyBlueprintConfig(t *testing.T) {
	n := (&tailcfg.Node{
		ID:              1,
		StableID:        "stable-1",
		BlueprintID:     "github-connector",
		BlueprintConfig: &tailcfg.BlueprintConfig{Tags: []string{"tag:bp//github-connector"}},
	}).View()
	var ps ipnstate.PeerStatus
	peerStatusFromNode(&ps, n)
	if ps.BlueprintID != "github-connector" {
		t.Errorf("BlueprintID = %q; want %q (BlueprintID should still propagate)", ps.BlueprintID, "github-connector")
	}
	if ps.BlueprintConfig != nil {
		t.Errorf("BlueprintConfig = %+v; want nil (only the Self-status path should populate it)", ps.BlueprintConfig)
	}
}

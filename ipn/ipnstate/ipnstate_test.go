// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnstate

import (
	"testing"

	"tailscale.com/types/key"
)

func TestAddPeerMergesBlueprintID(t *testing.T) {
	// Test 1: Empty value does not overwrite existing value
	var sb StatusBuilder
	k := key.NewNode().Public()
	sb.AddPeer(k, &PeerStatus{HostName: "node-a", BlueprintID: "github-connector"})
	// Second AddPeer with empty BlueprintID must NOT overwrite the
	// non-empty value previously stored — same pattern as every other
	// string field in AddPeer.
	sb.AddPeer(k, &PeerStatus{HostName: "node-a"})

	got := sb.Status().Peer[k]
	if got == nil {
		t.Fatalf("peer missing from status")
	}
	if got.BlueprintID != "github-connector" {
		t.Errorf("BlueprintID = %q; want %q", got.BlueprintID, "github-connector")
	}

	// Test 2: Fresh non-empty value DOES overwrite
	var sb2 StatusBuilder
	k2 := key.NewNode().Public()
	sb2.AddPeer(k2, &PeerStatus{HostName: "node-b", BlueprintID: "github-connector"})
	sb2.AddPeer(k2, &PeerStatus{HostName: "node-b", BlueprintID: "elsewhere"})
	got2 := sb2.Status().Peer[k2]
	if got2.BlueprintID != "elsewhere" {
		t.Errorf("after overwrite, BlueprintID = %q; want %q", got2.BlueprintID, "elsewhere")
	}
}

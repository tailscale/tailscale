// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build cgo || !darwin

package systray

import (
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestRecommendedIsActive(t *testing.T) {
	t.Parallel()

	const (
		activeID = tailcfg.StableNodeID("active")
		suggID   = tailcfg.StableNodeID("suggestion")
	)
	usNYC := &tailcfg.Location{CountryCode: "US", City: "New York"}
	usCHI := &tailcfg.Location{CountryCode: "US", City: "Chicago"}
	seSTO := &tailcfg.Location{CountryCode: "SE", City: "Stockholm"}

	statusWith := func(activePeer *ipnstate.PeerStatus) *ipnstate.Status {
		s := &ipnstate.Status{
			ExitNodeStatus: &ipnstate.ExitNodeStatus{ID: activeID},
		}
		if activePeer != nil {
			s.Peer = map[key.NodePublic]*ipnstate.PeerStatus{{}: activePeer}
		}
		return s
	}

	tests := []struct {
		name        string
		status      *ipnstate.Status
		suggID      tailcfg.StableNodeID
		suggCountry string
		suggCity    string
		isActive    bool
	}{
		{
			name:   "nil_status",
			status: nil,
			suggID: suggID,
		},
		{
			name:   "no_exit_node",
			status: &ipnstate.Status{},
			suggID: suggID,
		},
		{
			name:   "exit_node_id_is_zero",
			status: &ipnstate.Status{ExitNodeStatus: &ipnstate.ExitNodeStatus{}},
			suggID: suggID,
		},
		{
			name:        "exact_id_match_short-circuits",
			status:      statusWith(&ipnstate.PeerStatus{ID: activeID, Location: usCHI}),
			suggID:      activeID,
			suggCountry: "US",
			suggCity:    "New York",
			isActive:    true,
		},
		{
			name:        "id_mismatch_but_same_city",
			status:      statusWith(&ipnstate.PeerStatus{ID: activeID, Location: usNYC}),
			suggID:      suggID,
			suggCountry: "US",
			suggCity:    "New York",
			isActive:    true,
		},
		{
			name:        "different_city",
			status:      statusWith(&ipnstate.PeerStatus{ID: activeID, Location: usCHI}),
			suggID:      suggID,
			suggCountry: "US",
			suggCity:    "New York",
		},
		{
			name:        "different_country",
			status:      statusWith(&ipnstate.PeerStatus{ID: activeID, Location: seSTO}),
			suggID:      suggID,
			suggCountry: "US",
			suggCity:    "New York",
		},
		{
			name:   "id_mismatch_suggestion_has_no_location",
			status: statusWith(&ipnstate.PeerStatus{ID: activeID, Location: usNYC}),
			suggID: suggID,
		},
		{
			name:        "id_mismatch_active_peer_has_no_location",
			status:      statusWith(&ipnstate.PeerStatus{ID: activeID}),
			suggID:      suggID,
			suggCountry: "US",
			suggCity:    "New York",
		},
		{
			name:        "active_peer_not_in_status",
			status:      statusWith(nil),
			suggID:      suggID,
			suggCountry: "US",
			suggCity:    "New York",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			isExitNodeActive := recommendedIsActive(tt.status, tt.suggID, tt.suggCountry, tt.suggCity)
			if isExitNodeActive != tt.isActive {
				t.Errorf("recommendedIsActive; got %v, want %v", isExitNodeActive, tt.isActive)
			}
		})
	}
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsconsensus

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

type testStatusGetter struct {
	status *ipnstate.Status
}

func (sg testStatusGetter) getStatus(ctx context.Context) (*ipnstate.Status, error) {
	return sg.status, nil
}

const testTag string = "tag:clusterTag"

func makeAuthTestPeer(i int, tags views.Slice[string]) *ipnstate.PeerStatus {
	return &ipnstate.PeerStatus{
		ID:   tailcfg.StableNodeID(fmt.Sprintf("%d", i)),
		Tags: &tags,
		TailscaleIPs: []netip.Addr{
			netip.AddrFrom4([4]byte{100, 0, 0, byte(i)}),
			netip.MustParseAddr(fmt.Sprintf("fd7a:115c:a1e0:0::%d", i)),
		},
	}
}

func makeAuthTestPeers(tags [][]string) []*ipnstate.PeerStatus {
	peers := make([]*ipnstate.PeerStatus, len(tags))
	for i, ts := range tags {
		peers[i] = makeAuthTestPeer(i, views.SliceOf(ts))
	}
	return peers
}

func authForStatus(s *ipnstate.Status) *authorization {
	return &authorization{
		sg: testStatusGetter{
			status: s,
		},
		tag: testTag,
	}
}

func authForPeers(self *ipnstate.PeerStatus, peers []*ipnstate.PeerStatus) *authorization {
	s := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Self:         self,
		Peer:         map[key.NodePublic]*ipnstate.PeerStatus{},
	}
	for _, p := range peers {
		s.Peer[key.NewNode().Public()] = p
	}
	return authForStatus(s)
}

func TestAuthRefreshErrorsNotRunning(t *testing.T) {
	tests := []struct {
		in       *ipnstate.Status
		expected string
	}{
		{
			in:       nil,
			expected: "no status",
		},
		{
			in: &ipnstate.Status{
				BackendState: "NeedsMachineAuth",
			},
			expected: "ts Server is not running",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			ctx := t.Context()
			a := authForStatus(tt.in)
			err := a.Refresh(ctx)
			if err == nil {
				t.Fatalf("expected err to be non-nil")
			}
			if err.Error() != tt.expected {
				t.Fatalf("expected: %s, got: %s", tt.expected, err.Error())
			}
		})
	}
}

func TestAuthUnrefreshed(t *testing.T) {
	a := authForStatus(nil)
	if a.AllowsHost(netip.MustParseAddr("100.0.0.1")) {
		t.Fatalf("never refreshed authorization, allowsHost: expected false, got true")
	}
	gotAllowedPeers := a.AllowedPeers()
	if gotAllowedPeers.Len() != 0 {
		t.Fatalf("never refreshed authorization, allowedPeers: expected [], got %v", gotAllowedPeers)
	}
	if a.SelfAllowed() != false {
		t.Fatalf("never refreshed authorization, selfAllowed: expected false got true")
	}
}

func TestAuthAllowsHost(t *testing.T) {
	peerTags := [][]string{
		{"woo"},
		nil,
		{"woo", testTag},
		{testTag},
	}
	peers := makeAuthTestPeers(peerTags)

	tests := []struct {
		name       string
		peerStatus *ipnstate.PeerStatus
		expected   bool
	}{
		{
			name:       "tagged with different tag",
			peerStatus: peers[0],
			expected:   false,
		},
		{
			name:       "not tagged",
			peerStatus: peers[1],
			expected:   false,
		},
		{
			name:       "tags includes testTag",
			peerStatus: peers[2],
			expected:   true,
		},
		{
			name:       "only tag is testTag",
			peerStatus: peers[3],
			expected:   true,
		},
	}

	a := authForPeers(nil, peers)
	err := a.Refresh(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// test we get the expected result for any of the peers TailscaleIPs
			for _, addr := range tt.peerStatus.TailscaleIPs {
				got := a.AllowsHost(addr)
				if got != tt.expected {
					t.Fatalf("allowed for peer with tags: %v, expected: %t, got %t", tt.peerStatus.Tags, tt.expected, got)
				}
			}
		})
	}
}

func TestAuthAllowedPeers(t *testing.T) {
	ctx := t.Context()
	peerTags := [][]string{
		{"woo"},
		nil,
		{"woo", testTag},
		{testTag},
	}
	peers := makeAuthTestPeers(peerTags)
	a := authForPeers(nil, peers)
	err := a.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ps := a.AllowedPeers()
	if ps.Len() != 2 {
		t.Fatalf("expected: 2, got: %d", ps.Len())
	}
	for _, i := range []int{2, 3} {
		if !ps.ContainsFunc(func(p *ipnstate.PeerStatus) bool {
			return p.ID == peers[i].ID
		}) {
			t.Fatalf("expected peers[%d] to be in AllowedPeers because it is tagged with testTag", i)
		}
	}
}

func TestAuthSelfAllowed(t *testing.T) {
	tests := []struct {
		name     string
		in       []string
		expected bool
	}{
		{
			name:     "self has different tag",
			in:       []string{"woo"},
			expected: false,
		},
		{
			name:     "selfs tags include testTag",
			in:       []string{"woo", testTag},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			self := makeAuthTestPeer(0, views.SliceOf(tt.in))
			a := authForPeers(self, nil)
			err := a.Refresh(ctx)
			if err != nil {
				t.Fatal(err)
			}
			got := a.SelfAllowed()
			if got != tt.expected {
				t.Fatalf("expected: %t, got: %t", tt.expected, got)
			}
		})
	}
}

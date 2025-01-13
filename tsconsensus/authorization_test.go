// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsconsensus

import (
	"context"
	"net/netip"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
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

func authForStatus(s *ipnstate.Status) *authorization {
	return &authorization{
		sg: testStatusGetter{
			status: s,
		},
		tag: testTag,
	}
}

func addrsForIndex(i int) []netip.Addr {
	return []netip.Addr{
		netip.AddrFrom4([4]byte{100, 0, 0, byte(i)}),
		netip.AddrFrom4([4]byte{100, 0, 1, byte(i)}),
	}
}

func statusForTags(self []string, peers [][]string) *ipnstate.Status {
	selfTags := views.SliceOf(self)
	s := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Self: &ipnstate.PeerStatus{
			Tags: &selfTags,
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{},
	}
	for i, tagStrings := range peers {
		tags := views.SliceOf(tagStrings)
		s.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{
			Tags:         &tags,
			TailscaleIPs: addrsForIndex(i),
		}

	}
	return s
}

func authForTags(self []string, peers [][]string) *authorization {
	return authForStatus(statusForTags(self, peers))
}

func TestAuthRefreshErrorsNotRunning(t *testing.T) {
	ctx := context.Background()

	a := authForStatus(nil)
	err := a.Refresh(ctx)
	if err == nil {
		t.Fatalf("expected err to be non-nil")
	}
	expected := "no status"
	if err.Error() != expected {
		t.Fatalf("expected: %s, got: %s", expected, err.Error())
	}

	a = authForStatus(&ipnstate.Status{
		BackendState: "NeedsMachineAuth",
	})
	err = a.Refresh(ctx)
	if err == nil {
		t.Fatalf("expected err to be non-nil")
	}
	expected = "ts Server is not running"
	if err.Error() != expected {
		t.Fatalf("expected: %s, got: %s", expected, err.Error())
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
	ctx := context.Background()
	peerTags := [][]string{
		{"woo"},
		nil,
		{"woo", testTag},
		{testTag},
	}
	expected := []bool{
		false,
		false,
		true,
		true,
	}
	a := authForTags(nil, peerTags)
	err := a.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}

	for i, tags := range peerTags {
		for _, addr := range addrsForIndex(i) {
			got := a.AllowsHost(addr)
			if got != expected[i] {
				t.Fatalf("allowed %v, expected: %t, got %t", tags, expected[i], got)
			}
		}
	}
}

func TestAuthAllowedPeers(t *testing.T) {
	ctx := context.Background()
	a := authForTags(nil, [][]string{
		{"woo"},
		nil,
		{"woo", testTag},
		{testTag},
	})
	err := a.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ps := a.AllowedPeers()
	if ps.Len() != 2 {
		t.Fatalf("expected: 2, got: %d", ps.Len())
	}
}

func TestAuthSelfAllowed(t *testing.T) {
	ctx := context.Background()

	a := authForTags([]string{"woo"}, nil)
	err := a.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := a.SelfAllowed()
	if got {
		t.Fatalf("expected: false, got: %t", got)
	}

	a = authForTags([]string{"woo", testTag}, nil)
	err = a.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got = a.SelfAllowed()
	if !got {
		t.Fatalf("expected: true, got: %t", got)
	}
}

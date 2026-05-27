// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func mkPeer(host, bpID string, ip string) (key.NodePublic, *ipnstate.PeerStatus) {
	ps := &ipnstate.PeerStatus{
		HostName:    host,
		BlueprintID: bpID,
	}
	if ip != "" {
		ps.TailscaleIPs = []netip.Addr{netip.MustParseAddr(ip)}
	}
	return key.NewNode().Public(), ps
}

func TestRenderJoinStatus_NotBound(t *testing.T) {
	st := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Self:         &ipnstate.PeerStatus{},
	}
	var sb strings.Builder
	rc := renderJoinStatus(&sb, st)
	if rc != 1 {
		t.Errorf("returncode = %d; want 1", rc)
	}
	if !strings.Contains(sb.String(), "not blueprint-bound") {
		t.Errorf("output missing 'not blueprint-bound'; got:\n%s", sb.String())
	}
}

func TestRenderJoinStatus_BoundWithPeers(t *testing.T) {
	k1, p1 := mkPeer("node-a", "github-connector", "100.64.0.5")
	k2, p2 := mkPeer("node-b", "github-connector", "100.64.0.7")
	k3, p3 := mkPeer("other", "different", "100.64.0.99")
	k4, p4 := mkPeer("nobinding", "", "100.64.0.100")
	st := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Self: &ipnstate.PeerStatus{
			BlueprintID: "github-connector",
			BlueprintConfig: &tailcfg.BlueprintConfig{
				Tags: []string{"tag:bp//github-connector"},
			},
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			k1: p1, k2: p2, k3: p3, k4: p4,
		},
	}
	var sb strings.Builder
	rc := renderJoinStatus(&sb, st)
	if rc != 0 {
		t.Errorf("returncode = %d; want 0", rc)
	}
	out := sb.String()
	if !strings.Contains(out, "Blueprint:  bp:github-connector") {
		t.Errorf("missing projection header; got:\n%s", out)
	}
	if !strings.Contains(out, "Tags:      tag:bp//github-connector") {
		t.Errorf("missing tags line; got:\n%s", out)
	}
	if !strings.Contains(out, "Peers bound to bp:github-connector (2 visible)") {
		t.Errorf("missing peer count; got:\n%s", out)
	}
	if !strings.Contains(out, "node-a") || !strings.Contains(out, "node-b") {
		t.Errorf("missing peer hostnames; got:\n%s", out)
	}
	if strings.Contains(out, "other") || strings.Contains(out, "nobinding") {
		t.Errorf("output includes peers with a different/empty BlueprintID; got:\n%s", out)
	}
	// Hostname sort order: node-a before node-b.
	if i, j := strings.Index(out, "node-a"), strings.Index(out, "node-b"); i < 0 || j < 0 || i > j {
		t.Errorf("peers not sorted by hostname; got:\n%s", out)
	}
}

func TestRenderJoinStatus_BoundNoPeers(t *testing.T) {
	st := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Self: &ipnstate.PeerStatus{
			BlueprintID:     "lonely",
			BlueprintConfig: &tailcfg.BlueprintConfig{},
		},
	}
	var sb strings.Builder
	rc := renderJoinStatus(&sb, st)
	if rc != 0 {
		t.Errorf("returncode = %d; want 0", rc)
	}
	if !strings.Contains(sb.String(), "No other peers bound to bp:lonely are visible") {
		t.Errorf("missing no-peers message; got:\n%s", sb.String())
	}
}

func TestRenderJoinStatus_BoundProjectionNil(t *testing.T) {
	st := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Self: &ipnstate.PeerStatus{
			BlueprintID:     "foo",
			BlueprintConfig: nil,
		},
	}
	var sb strings.Builder
	rc := renderJoinStatus(&sb, st)
	if rc != 0 {
		t.Errorf("returncode = %d; want 0", rc)
	}
	if !strings.Contains(sb.String(), "(projection not yet received)") {
		t.Errorf("missing projection-pending line; got:\n%s", sb.String())
	}
}

func TestRenderJoinStatusJSON(t *testing.T) {
	k1, p1 := mkPeer("node-a", "foo", "100.64.0.5")
	st := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Self: &ipnstate.PeerStatus{
			BlueprintID:     "foo",
			BlueprintConfig: &tailcfg.BlueprintConfig{Tags: []string{"tag:bp//foo"}},
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{k1: p1},
	}
	var sb strings.Builder
	rc := renderJoinStatusJSON(&sb, st)
	if rc != 0 {
		t.Errorf("returncode = %d; want 0", rc)
	}
	var out joinStatusJSON
	if err := json.Unmarshal([]byte(sb.String()), &out); err != nil {
		t.Fatalf("invalid JSON: %v\noutput: %s", err, sb.String())
	}
	if out.BlueprintID != "foo" {
		t.Errorf("BlueprintID = %q; want %q", out.BlueprintID, "foo")
	}
	if out.BlueprintConfig == nil || len(out.BlueprintConfig.Tags) != 1 {
		t.Errorf("BlueprintConfig.Tags = %v; want one entry", out.BlueprintConfig)
	}
	if len(out.BoundPeers) != 1 || out.BoundPeers[0].HostName != "node-a" {
		t.Errorf("BoundPeers = %+v; want one entry for node-a", out.BoundPeers)
	}
}

func TestRenderJoinStatusJSON_NotBound(t *testing.T) {
	st := &ipnstate.Status{Self: &ipnstate.PeerStatus{}}
	var sb strings.Builder
	rc := renderJoinStatusJSON(&sb, st)
	if rc != 1 {
		t.Errorf("returncode = %d; want 1", rc)
	}
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"fmt"
	"testing"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
)

func TestFileTargets(t *testing.T) {
	e := new(Extension)

	_, err := e.FileTargets()
	if got, want := fmt.Sprint(err), "not connected to the tailnet"; got != want {
		t.Errorf("before connect: got %q; want %q", got, want)
	}

	e.nodeBackendForTest = testNodeBackend{peers: nil}

	_, err = e.FileTargets()
	if got, want := fmt.Sprint(err), "not connected to the tailnet"; got != want {
		t.Errorf("non-running netmap: got %q; want %q", got, want)
	}

	e.backendState = ipn.Running
	_, err = e.FileTargets()
	if got, want := fmt.Sprint(err), "file sharing not enabled by Tailscale admin"; got != want {
		t.Errorf("without cap: got %q; want %q", got, want)
	}

	e.capFileSharing = true
	got, err := e.FileTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected %d peers", len(got))
	}

	var nodeID tailcfg.NodeID = 1234
	peer := &tailcfg.Node{
		ID:       nodeID,
		Hostinfo: (&tailcfg.Hostinfo{OS: "tvOS"}).View(),
	}
	e.nodeBackendForTest = testNodeBackend{peers: []tailcfg.NodeView{peer.View()}}

	got, err = e.FileTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected %d peers", len(got))
	}
}

type testNodeBackend struct {
	ipnext.NodeBackend
	peers      []tailcfg.NodeView
	self       tailcfg.NodeView
	hasPeerAPI bool
	peerHasCap bool
}

func (t testNodeBackend) Self() tailcfg.NodeView                        { return t.self }
func (t testNodeBackend) PeerHasPeerAPI(tailcfg.NodeView) bool          { return t.hasPeerAPI }
func (t testNodeBackend) PeerHasCap(tailcfg.NodeView, peercap.Cap) bool { return t.peerHasCap }

func (t testNodeBackend) AppendMatchingPeers(peers []tailcfg.NodeView, f func(tailcfg.NodeView) bool) []tailcfg.NodeView {
	for _, p := range t.peers {
		if f(p) {
			peers = append(peers, p)
		}
	}
	return peers
}

// TestTaildropTargetStatus checks the status reported to the sending side
// agrees with the rule the receiving side applies, and in particular that no
// peer capability changes it.
//
// Reporting a peer as Available promises the transfer won't be held up for
// approval, so it must only be said where that's true.
func TestTaildropTargetStatus(t *testing.T) {
	const selfUID tailcfg.UserID = 1
	const otherUID tailcfg.UserID = 2

	peerNode := func(uid tailcfg.UserID, tagged bool) tailcfg.NodeView {
		n := &tailcfg.Node{ID: 1, User: uid, Cap: tailcfg.CurrentCapabilityVersion + 1, Hostinfo: (&tailcfg.Hostinfo{OS: "linux"}).View()}
		n.Online = new(true)
		if tagged {
			n.Tags = []string{"tag:peer"}
		}
		return n.View()
	}

	tests := []struct {
		name       string
		peer       tailcfg.NodeView
		selfTagged bool
		peerHasCap bool
		want       ipnstate.TaildropTargetStatus
	}{
		{"own_untagged", peerNode(selfUID, false), false, false, ipnstate.TaildropTargetAvailable},
		{"own_tagged", peerNode(selfUID, true), false, false, ipnstate.TaildropTargetMissingCap},
		{"own_untagged_self_tagged", peerNode(selfUID, false), true, false, ipnstate.TaildropTargetMissingCap},
		{"other_user", peerNode(otherUID, false), false, false, ipnstate.TaildropTargetMissingCap},

		// The point of this test: an ACL capability must not turn a prompt
		// into a promise that there won't be one.
		{"other_user_with_cap", peerNode(otherUID, false), false, true, ipnstate.TaildropTargetMissingCap},
		{"own_tagged_with_cap", peerNode(selfUID, true), false, true, ipnstate.TaildropTargetMissingCap},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			self := &tailcfg.Node{ID: 99, User: selfUID}
			if tt.selfTagged {
				self.Tags = []string{"tag:self"}
			}
			e := &Extension{backendState: ipn.Running, selfUID: selfUID, capFileSharing: true}
			nb := testNodeBackend{self: self.View(), hasPeerAPI: true, peerHasCap: tt.peerHasCap}
			if got := e.taildropTargetStatus(tt.peer, nb); got != tt.want {
				t.Errorf("taildropTargetStatus = %v; want %v", got, tt.want)
			}
		})
	}
}

func (t testNodeBackend) PeerAPIBase(tailcfg.NodeView) string {
	if t.hasPeerAPI {
		return "http://100.64.0.1:1234"
	}
	return ""
}

// TestConsentTargetPlatformSupport verifies that target discovery and UI status
// agree about platform and protocol support, while same-user untagged transfers
// retain legacy compatibility.
func TestConsentTargetPlatformSupport(t *testing.T) {
	tests := []struct {
		name       string
		os         string
		capVersion tailcfg.CapabilityVersion
		own        bool
		peerTagged bool
		selfTagged bool
		wantTarget bool
		wantStatus ipnstate.TaildropTargetStatus
	}{
		{name: "linux", os: "linux", capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "freebsd", os: "freebsd", capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "openbsd", os: "openbsd", capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "macos_no_ui", os: "macOS", capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "ios_no_ui", os: "iOS", capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "linux_old_backend", os: "linux", capVersion: tailcfg.CurrentCapabilityVersion, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "linux_newer_backend", os: "linux", capVersion: tailcfg.CurrentCapabilityVersion + 2, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "windows_old_backend", os: "windows", capVersion: tailcfg.CurrentCapabilityVersion, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "android_old_backend", os: "android", capVersion: tailcfg.CurrentCapabilityVersion, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "linux_no_backend", os: "linux", wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "macos_no_backend", os: "macOS", wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "ios_no_backend", os: "iOS", wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "tvos", os: "tvOS", capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "missing_os", capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},

		{name: "macos_future_version_no_ui", os: "macOS", capVersion: tailcfg.CurrentCapabilityVersion + 2, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "ios_future_version_no_ui", os: "iOS", capVersion: tailcfg.CurrentCapabilityVersion + 2, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "darwin_future_version_no_ui", os: "darwin", capVersion: tailcfg.CurrentCapabilityVersion + 2, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "darwin_no_ui", os: "darwin", capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "windows_future_version_no_ui", os: "windows", capVersion: tailcfg.CurrentCapabilityVersion + 2, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "android_future_version_no_ui", os: "android", capVersion: tailcfg.CurrentCapabilityVersion + 2, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "windows_no_ui", os: "windows", capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "windows_no_backend", os: "windows", wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "android_no_ui", os: "android", capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "android_no_backend", os: "android", wantStatus: ipnstate.TaildropTargetMissingCap},

		{name: "own_linux", os: "linux", own: true, wantTarget: true, wantStatus: ipnstate.TaildropTargetAvailable},
		{name: "own_macos", os: "macOS", own: true, wantTarget: true, wantStatus: ipnstate.TaildropTargetAvailable},
		{name: "own_ios", os: "iOS", own: true, wantTarget: true, wantStatus: ipnstate.TaildropTargetAvailable},
		{name: "own_darwin", os: "darwin", own: true, wantTarget: true, wantStatus: ipnstate.TaildropTargetAvailable},
		{name: "own_windows", os: "windows", own: true, wantTarget: true, wantStatus: ipnstate.TaildropTargetAvailable},
		{name: "own_android", os: "android", own: true, wantTarget: true, wantStatus: ipnstate.TaildropTargetAvailable},
		{name: "own_tvos", os: "tvOS", own: true, wantStatus: ipnstate.TaildropTargetUnsupportedOS},
		{name: "own_missing_os", own: true, wantTarget: true, wantStatus: ipnstate.TaildropTargetAvailable},

		{name: "macos_peer_tagged_no_ui", os: "macOS", own: true, peerTagged: true, capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "macos_self_tagged_no_ui", os: "macOS", own: true, selfTagged: true, capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "ios_peer_tagged_no_ui", os: "iOS", own: true, peerTagged: true, capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "ios_self_tagged_no_ui", os: "iOS", own: true, selfTagged: true, capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "darwin_peer_tagged_no_ui", os: "darwin", own: true, peerTagged: true, capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "darwin_self_tagged_no_ui", os: "darwin", own: true, selfTagged: true, capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "windows_peer_tagged_no_ui", os: "windows", own: true, peerTagged: true, capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "windows_self_tagged_no_ui", os: "windows", own: true, selfTagged: true, capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "android_peer_tagged_no_ui", os: "android", own: true, peerTagged: true, capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
		{name: "android_self_tagged_no_ui", os: "android", own: true, selfTagged: true, capVersion: tailcfg.CurrentCapabilityVersion + 1, wantStatus: ipnstate.TaildropTargetMissingCap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := &tailcfg.Node{
				ID: 2, User: 2, Online: new(true),
				Hostinfo: (&tailcfg.Hostinfo{OS: tt.os}).View(),
			}
			self := &tailcfg.Node{ID: 1, User: 1}
			if tt.own {
				peer.User = self.User
			}
			if tt.peerTagged {
				peer.Tags = []string{"tag:receiver"}
			}
			if tt.selfTagged {
				self.Tags = []string{"tag:sender"}
			}
			peer.Cap = tt.capVersion
			e := &Extension{selfUID: 1, backendState: ipn.Running, capFileSharing: true}
			nb := testNodeBackend{self: self.View(), peers: []tailcfg.NodeView{peer.View()}, hasPeerAPI: true}
			e.nodeBackendForTest = nb
			got, err := e.FileTargets()
			if err != nil || (len(got) == 1) != tt.wantTarget {
				t.Fatalf("FileTargets = %v, %v; want target=%v", got, err, tt.wantTarget)
			}
			if got := e.taildropTargetStatus(peer.View(), nb); got != tt.wantStatus {
				t.Errorf("taildropTargetStatus = %v; want %v", got, tt.wantStatus)
			}
		})
	}
}

// TestForcedOwnConsent verifies that forced same-user consent requires opt-in
// for both the sender's consent exchange and the status advertised to the UI,
// including after opting out.
func TestForcedOwnConsent(t *testing.T) {
	envknob.SetenvForTest(t, "TS_DEBUG_TAILDROP_CONSENT", "true")
	const uid tailcfg.UserID = 1
	self := (&tailcfg.Node{User: uid}).View()
	peer := (&tailcfg.Node{
		StableID: "own", User: uid, Cap: tailcfg.CurrentCapabilityVersion + 1, Online: new(true),
		Hostinfo: (&tailcfg.Hostinfo{OS: "iOS"}).View(),
	}).View()
	nb := testNodeBackend{self: self, peers: []tailcfg.NodeView{peer}, hasPeerAPI: true}
	e := &Extension{
		selfUID: uid, backendState: ipn.Running, capFileSharing: true,
		nodeBackendForTest: nb,
	}
	for _, enabled := range []bool{false, true, false} {
		e.allowExternalTaildrop.Store(enabled)
		want := enabled
		if got := e.shouldRequestConsent(peer.StableID()); got != want {
			t.Errorf("opt-in=%v: shouldRequestConsent=%v, want %v", enabled, got, want)
		}
		wantStatus := ipnstate.TaildropTargetAvailable
		if want {
			wantStatus = ipnstate.TaildropTargetConsentRequired
		}
		if got := e.taildropTargetStatus(peer, nb); got != wantStatus {
			t.Errorf("opt-in=%v: status=%v, want %v", enabled, got, wantStatus)
		}
	}
}

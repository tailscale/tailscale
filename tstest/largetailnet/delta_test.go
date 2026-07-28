// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package largetailnet_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/tstest/largetailnet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/wgengine/filter"
)

// metricByName returns the [clientmetric.Metric] with the given name,
// failing the test if not found.
func metricByName(t testing.TB, name string) *clientmetric.Metric {
	t.Helper()
	for _, m := range clientmetric.Metrics() {
		if m.Name() == name {
			return m
		}
	}
	t.Fatalf("metric %q not found", name)
	return nil
}

// TestNetmapDeltaFastPath drives a sequence of MapResponses against an
// in-process tsnet + testcontrol harness via [largetailnet.Streamer]'s
// AltMapStream hook, exercising every delta-message kind the
// incremental netmap path handles. After each delta it asserts both:
//
//   - the appropriate fast-path metric counters incremented (i.e. we
//     stayed on the incremental path and did not fall through to a full
//     netmap rebuild); and
//
//   - the corresponding side effect is observable on the [LocalBackend]
//     (a fresh peer resolvable via PeerByID, a UserProfile resolvable
//     via UserProfile, a packet filter rule reflected in
//     ForTest().GetFilter, a per-field patch reflected in PeerByID, etc.).
//
// This is the destination-side companion to
// [tstest/largetailnet/BenchmarkGiantTailnet], which only measures cost
// of the same fast path — this test verifies correctness.
func TestNetmapDeltaFastPath(t *testing.T) {

	logf := logger.Discard
	if testing.Verbose() {
		logf = t.Logf
	}

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)

	derpMap := integration.RunDERPAndSTUN(t, logf, "127.0.0.1")

	// Start with one initial peer (NodeID 2) so the initial netmap is
	// realistic. The fast path will not fire for the initial response —
	// it always goes through UpdateFullNetmap — but every subsequent
	// SendDelta should.
	streamer := largetailnet.New(1, derpMap)
	ctrl := &testcontrol.Server{
		DERPMap:      derpMap,
		DNSConfig:    &tailcfg.DNSConfig{},
		AltMapStream: streamer.AltMapStream(),
		Logf:         logf,
	}
	ctrl.HTTPTestServer = httptest.NewUnstartedServer(ctrl)
	ctrl.HTTPTestServer.Start()
	t.Cleanup(ctrl.HTTPTestServer.Close)

	tmp := filepath.Join(t.TempDir(), "tsnet")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &tsnet.Server{
		Dir:        tmp,
		ControlURL: ctrl.HTTPTestServer.URL,
		Hostname:   "delta-test",
		Store:      new(mem.Store),
		Ephemeral:  true,
		Logf:       logf,
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Up(ctx); err != nil {
		t.Fatalf("tsnet.Server.Up: %v", err)
	}
	lb := tsnet.TestHooks.LocalBackend(s)

	// Snapshot baseline metric values; we'll assert deltas against
	// these. Globals make per-test isolation impossible, but deltas
	// are robust against interleaving (assuming no other test runs in
	// parallel here).
	mFast := metricByName(t, "controlclient_map_response_handled_incrementally")
	mFull := metricByName(t, "controlclient_map_response_handled_full_rebuild")
	mUpsert := metricByName(t, "localbackend_netmap_delta_peer_upserted")
	mRem := metricByName(t, "localbackend_netmap_delta_peer_removed")
	mPatch := metricByName(t, "localbackend_netmap_delta_peer_patched")
	mFilter := metricByName(t, "localbackend_update_packet_filter")
	mUsers := metricByName(t, "localbackend_update_user_profiles")
	baseline := map[*clientmetric.Metric]int64{
		mFast: mFast.Value(), mFull: mFull.Value(),
		mUpsert: mUpsert.Value(), mRem: mRem.Value(), mPatch: mPatch.Value(),
		mFilter: mFilter.Value(), mUsers: mUsers.Value(),
	}
	dumpMetrics := func(t *testing.T) {
		t.Helper()
		for _, m := range []*clientmetric.Metric{mFast, mFull, mUpsert, mRem, mPatch, mFilter, mUsers} {
			t.Logf("metric %s = %d (baseline %d, delta %d)", m.Name(), m.Value(), baseline[m], m.Value()-baseline[m])
		}
	}
	waitDelta := func(t *testing.T, m *clientmetric.Metric, want int64) {
		t.Helper()
		err := tstest.WaitFor(2*time.Second, func() error {
			got := m.Value() - baseline[m]
			if got >= want {
				return nil
			}
			return fmt.Errorf("%s delta = %d, want >= %d", m.Name(), got, want)
		})
		if err != nil {
			dumpMetrics(t)
			t.Fatalf("%s: %v", m.Name(), err)
		}
		if got := m.Value() - baseline[m]; got != want {
			t.Errorf("%s delta = %d, want exactly %d", m.Name(), got, want)
		}
		baseline[m] = m.Value()
	}

	// Helper to send a MapResponse and wait for it to be processed by
	// the client. We use the metric deltas as our synchronization
	// point: SendDelta is synchronous from the streamer side, but the
	// client processes the response on its own goroutine, so we wait
	// for the fast-path counter to tick.
	sendDelta := func(t *testing.T, mr *tailcfg.MapResponse) {
		t.Helper()
		if err := streamer.SendDelta(ctx, mr); err != nil {
			t.Fatalf("SendDelta: %v", err)
		}
	}

	// Self IPv4, used as the destination in packet filter checks below.
	// largetailnet derives self addresses from SelfNodeID via node4/node6;
	// for SelfNodeID=1 that's 100.100.0.1.
	selfIP4 := netip.MustParseAddr("100.100.0.1")

	// addedPeerID is set by the peer_added_with_filter_and_user_profile
	// subtest and consumed later by peer_removed.
	var addedPeerID tailcfg.NodeID

	t.Run("peer_added_with_filter_and_user_profile", func(t *testing.T) {
		// Add a fresh peer. Bundle a new PacketFilter rule allowing
		// TCP from that peer's IP to a port we'll later probe, and a
		// new UserProfile for the user that owns the new peer.
		newPeer := streamer.AllocPeer()
		newUser := tailcfg.UserID(42)
		newPeer.User = newUser
		newPeer.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.42/32")}
		addedPeerID = newPeer.ID
		sendDelta(t, &tailcfg.MapResponse{
			PeersChanged: []*tailcfg.Node{newPeer},
			PacketFilter: []tailcfg.FilterRule{{
				SrcIPs:   []string{"100.64.0.42/32"},
				IPProto:  []int{int(ipproto.TCP)},
				DstPorts: []tailcfg.NetPortRange{{IP: "*", Ports: tailcfg.PortRange{First: 22, Last: 22}}},
			}},
			UserProfiles: []tailcfg.UserProfile{{
				ID:          newUser,
				LoginName:   "alice@example.com",
				DisplayName: "Alice",
			}},
		})

		waitDelta(t, mFast, 1)
		waitDelta(t, mUpsert, 1)
		waitDelta(t, mFilter, 1)
		waitDelta(t, mUsers, 1)
		waitDelta(t, mFull, 0)

		// Side effects.
		nv, ok := lb.PeerByID(newPeer.ID)
		if !ok || nv.ID() != newPeer.ID {
			t.Errorf("PeerByID(%d) ok=%v node=%v", newPeer.ID, ok, nv)
		}
		uv, ok := lb.UserProfile(newUser)
		if !ok || uv.LoginName() != "alice@example.com" {
			t.Errorf("UserProfile(%d) ok=%v login=%q", newUser, ok, uv.LoginName())
		}
		pf := lb.ForTest().GetFilter()
		if got := pf.Check(netip.MustParseAddr("100.64.0.42"), selfIP4, 22, ipproto.TCP); got != filter.Accept {
			t.Errorf("packet filter Check from new peer = %s; want Accept", got)
		}
	})

	t.Run("peer_patch_derp_home", func(t *testing.T) {
		// Patch the initial peer's DERPRegion via PeersChangedPatch.
		// This rides as NodeMutationDERPHome.
		sendDelta(t, &tailcfg.MapResponse{
			PeersChangedPatch: []*tailcfg.PeerChange{{
				NodeID:     2,
				DERPRegion: 7,
			}},
		})

		waitDelta(t, mFast, 1)
		waitDelta(t, mPatch, 1)
		waitDelta(t, mFull, 0)

		nv, ok := lb.PeerByID(2)
		if !ok {
			t.Fatalf("PeerByID(2) not found")
		}
		if got := nv.HomeDERP(); got != 7 {
			t.Errorf("HomeDERP = %d, want 7", got)
		}
	})

	t.Run("peer_online_and_last_seen", func(t *testing.T) {
		// Online + LastSeen on the same delta. PeerSeenChange's value
		// is true to set LastSeen, false to clear it; the time it gets
		// is now() at the time MutationsFromMapResponse runs on the
		// client, not a wire value.
		sendDelta(t, &tailcfg.MapResponse{
			OnlineChange:   map[tailcfg.NodeID]bool{2: true},
			PeerSeenChange: map[tailcfg.NodeID]bool{2: true},
		})

		waitDelta(t, mFast, 1)
		// Two mutations: one NodeMutationOnline + one NodeMutationLastSeen.
		waitDelta(t, mPatch, 2)
		waitDelta(t, mFull, 0)

		nv, ok := lb.PeerByID(2)
		if !ok {
			t.Fatalf("PeerByID(2) not found")
		}
		if o := nv.Online(); !o.Valid() || !o.Get() {
			t.Errorf("Online = %v, want true", o)
		}
	})

	t.Run("peer_removed", func(t *testing.T) {
		if addedPeerID == 0 {
			t.Fatal("peer_added_with_filter_and_user_profile must run first")
		}
		// Sanity check: the peer should currently exist.
		if _, ok := lb.PeerByID(addedPeerID); !ok {
			t.Fatalf("PeerByID(%d) missing before removal", addedPeerID)
		}

		sendDelta(t, &tailcfg.MapResponse{
			PeersRemoved: []tailcfg.NodeID{addedPeerID},
		})

		waitDelta(t, mFast, 1)
		waitDelta(t, mRem, 1)
		waitDelta(t, mFull, 0)

		if _, ok := lb.PeerByID(addedPeerID); ok {
			t.Errorf("PeerByID(%d) still present after PeersRemoved", addedPeerID)
		}
	})
}

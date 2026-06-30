// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

// These tests pin down that Tailnet Lock's signature filter
// ([LocalBackend.tkaFilterNetmapLocked] on full netmaps, and
// [LocalBackend.tkaFilterDeltaMutsLocked] on netmap deltas) catches
// unsigned and invalidly-signed peers arriving via the netmap delta
// path. The tsnet package is a slightly awkward home for them: the
// behavior under test lives in [ipn/ipnlocal], not in tsnet itself.
// They live here because:
//
//   - tsnet has the right harness: a real [tsnet.Server] joined to a
//     [testcontrol.Server], with a working noise channel for the
//     /machine/tka/* RPC dance that enables Tailnet Lock and signs the
//     local node key. Standing the equivalent up directly under
//     [ipn/ipnlocal] would mean recreating large parts of that.
//
//   - [ipn/ipnlocal/tailnet-lock_test.go] tests
//     [tkaFilterNetmapLocked] against a hand-built netmap, but doesn't
//     exercise the wire path through [controlclient] and
//     [LocalBackend.UpdateNetmapDelta] where these regressions
//     actually surface.
//
//   - [tstest/integration] does drive a real tailscaled but its harness
//     is heavier (forking the binary, no [testcontrol.Server.AddRawMapResponse]
//     hook), and we want the precision of synthetic delta injection.
//
// If a smaller harness ever lands that lets [ipn/ipnlocal] tests drive
// the full controlclient->LocalBackend pipe with raw MapResponses,
// these tests should move there.

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/tkatype"
	"tailscale.com/util/must"
)

// setupTailnetLockedServer brings up a tsnet [Server] under a testcontrol
// [Server] with Tailnet Lock enabled and ready to take injected raw
// [tailcfg.MapResponse]s. The returned *Server has:
//
//   - the [tailcfg.CapabilityTailnetLock] capability on its self node,
//   - Tailnet Lock initialized with trustedKeys (always including the
//     self node's own NL public key, plus any extras the caller supplies),
//   - a valid self [tailcfg.Node.KeySignature], and
//     [netmap.NetworkMap.TKAEnabled] true, so [LocalBackend.tkaFilterNetmapLocked]
//     is wired up and would catch unsigned peers if invoked on subsequent
//     deltas, and
//   - control's auto-MapResponse generation suppressed: from here on, only
//     raw responses the caller pushes via [testcontrol.Server.AddRawMapResponse]
//     reach the node.
//
// Tests for Tailnet Lock's interaction with the delta path build on top of
// this helper and only need to inject the specific delta they want to
// exercise.
func setupTailnetLockedServer(t *testing.T, ctx context.Context, extraTrustedKeys ...tka.Key) (s *Server, control *testcontrol.Server, s1Key key.NodePublic) {
	t.Helper()
	controlURL, control := startControl(t)

	// Hand out the tailnet-lock capability so the server can call
	// TailnetLockInit.
	control.DefaultNodeCapabilities = &tailcfg.NodeCapMap{
		tailcfg.CapabilityTailnetLock: nil,
	}

	s, _, s1Key = startServer(t, ctx, controlURL, "s1")

	// Enable Tailnet Lock with the node's own NL public key plus any
	// extras the caller supplied. This drives the /machine/tka/init/{begin,
	// finish} dance against testcontrol; on finish, control stores a valid
	// KeySignature for the node and the next auto-generated MapResponse
	// will carry TKAInfo + the signature.
	lc := must.Get(s.LocalClient())
	tkaStatus := must.Get(lc.TailnetLockStatus(ctx))
	trustedKeys := append([]tka.Key{
		{Kind: tka.Key25519, Public: tkaStatus.PublicKey.Verifier(), Votes: 2},
	}, extraTrustedKeys...)
	disablementSecret := bytes.Repeat([]byte{0xa5}, 32)
	if _, err := lc.TailnetLockInit(ctx, trustedKeys,
		[][]byte{tka.DisablementKDF(disablementSecret)}, nil); err != nil {
		t.Fatalf("TailnetLockInit: %v", err)
	}

	// testcontrol's serveTKAInitFinish stores signatures but doesn't wake
	// up the streaming map long-poll. Re-publish the node to wake it, so
	// the next MapResponse carries TKAInfo + the new self KeySignature.
	control.UpdateNode(control.Node(s1Key))

	// Wait for the node to receive the netmap that turns Tailnet Lock on
	// and carries a valid self-node signature. At that point
	// [LocalBackend.tkaSyncIfNeeded] has bootstrapped b.tka locally, so
	// any subsequent peer arrival is subject to tkaFilterNetmapLocked
	// when it goes through the full-netmap path.
	if err := waitFor(t, ctx, s, func(nm *netmap.NetworkMap) bool {
		return nm.TKAEnabled && nm.SelfNode.KeySignature().Len() > 0
	}); err != nil {
		t.Fatalf("waitFor s1 to enable Tailnet Lock: %v", err)
	}

	// Switch the node into manual MapResponse mode so any further peer
	// state can only reach it via raw responses the caller injects.
	if !control.AddRawMapResponse(s1Key, &tailcfg.MapResponse{}) {
		t.Fatal("AddRawMapResponse(s1, empty): node not connected")
	}
	return s, control, s1Key
}

// signNodeKeyForTest signs nodeKey with nlPriv. It is a copy of the
// (unexported) signNodeKey in ipn/ipnlocal/tailnet-lock.go, replicated
// here so tsnet tests can mint valid signatures without cyclically
// depending on ipnlocal internals.
func signNodeKeyForTest(t *testing.T, nodeKey key.NodePublic, nlPriv key.NLPrivate) tkatype.MarshaledSignature {
	t.Helper()
	pub, err := nodeKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sig := tka.NodeKeySignature{
		SigKind: tka.SigDirect,
		KeyID:   nlPriv.KeyID(),
		Pubkey:  pub,
	}
	sig.Signature, err = nlPriv.SignNKS(sig.SigHash())
	if err != nil {
		t.Fatalf("SignNKS: %v", err)
	}
	return sig.Serialize()
}

// signedMarkerPeer constructs a fresh Node signed by nlPriv, suitable
// for use as a delta-sync sentinel: tests can append it to a
// [tailcfg.MapResponse.PeersChanged] alongside the actual fixture and
// then waitFor the marker key to appear in nm.Peers. Because the
// MapResponse delivers all entries atomically as a single delta,
// observing the marker proves the preceding entries in the same
// PeersChanged batch have already been processed end-to-end through
// [LocalBackend.UpdateNetmapDelta]. That makes the absence-of-fixture
// assertion race-free without having to wait a fixed timeout for
// "nothing to happen".
func signedMarkerPeer(t *testing.T, nlPriv key.NLPrivate) *tailcfg.Node {
	t.Helper()
	markerKey := key.NewNode().Public()
	markerAddr := netip.MustParsePrefix("100.64.99.250/32")
	return &tailcfg.Node{
		ID:                tailcfg.NodeID(10000),
		StableID:          tailcfg.StableNodeID("TESTMARKER0000001"),
		Name:              "marker.test.",
		Key:               markerKey,
		Machine:           key.NewMachine().Public(),
		DiscoKey:          key.NewDisco().Public(),
		Addresses:         []netip.Prefix{markerAddr},
		AllowedIPs:        []netip.Prefix{markerAddr},
		MachineAuthorized: true,
		KeySignature:      signNodeKeyForTest(t, markerKey, nlPriv),
	}
}

// injectPeersChangedAndAssertFiltered pushes badPeer alongside a fresh
// signed marker peer in a single [tailcfg.MapResponse.PeersChanged]
// batch, then waits for the marker to land in s's netmap. Observing
// the marker means the whole batch was applied end-to-end through
// [LocalBackend.UpdateNetmapDelta], so the helper can then make a
// race-free assertion that badPeer.Key is absent from
// [LocalBackend.NetMapWithPeers]. markerNL must be a private NL key
// whose public verifier is trusted by the tailnet-lock state on s
// (e.g. an extra key passed to [setupTailnetLockedServer]).
func injectPeersChangedAndAssertFiltered(t *testing.T, ctx context.Context, s *Server, control *testcontrol.Server, dst key.NodePublic, badPeer *tailcfg.Node, markerNL key.NLPrivate) {
	t.Helper()
	marker := signedMarkerPeer(t, markerNL)
	if !control.AddRawMapResponse(dst, &tailcfg.MapResponse{
		PeersChanged: []*tailcfg.Node{badPeer, marker},
	}) {
		t.Fatal("AddRawMapResponse(PeersChanged): node not connected")
	}
	if err := waitFor(t, ctx, s, func(nm *netmap.NetworkMap) bool {
		for _, p := range nm.Peers {
			if p.Key() == marker.Key {
				return true
			}
		}
		return false
	}); err != nil {
		t.Fatalf("waitFor marker peer to land: %v", err)
	}
	for _, p := range s.lb.NetMapWithPeers().Peers {
		if p.Key() == badPeer.Key {
			t.Fatalf("peer %q (key %v, KeySignature.Len=%d) leaked into s.NetMap.Peers via PeersChanged delta path; Tailnet Lock filter not applied to deltas",
				badPeer.Name, badPeer.Key, p.KeySignature().Len())
		}
	}

	// Verify TailnetLockStatus via LocalAPI: the bad peer must appear
	// in FilteredPeers.
	lc := must.Get(s.LocalClient())
	st := must.Get(lc.TailnetLockStatus(ctx))
	var badInFiltered bool
	for _, fp := range st.FilteredPeers {
		if fp.NodeKey == badPeer.Key {
			badInFiltered = true
			break
		}
	}
	if !badInFiltered {
		t.Errorf("TailnetLockStatus().FilteredPeers does not contain bad peer %v; got %d entries", badPeer.Key, len(st.FilteredPeers))
	}
}

// TestTailnetLockFiltersUnsignedDeltaPeer verifies that with Tailnet Lock
// enabled, an unsigned peer arriving via [tailcfg.MapResponse.PeersChanged]
// is dropped from the local netmap, just like one arriving in a full
// [tailcfg.MapResponse.Peers] list.
//
// Background: [LocalBackend.tkaFilterNetmapLocked] is the canonical
// chokepoint for Tailnet Lock; it runs on full netmaps via
// [LocalBackend.setClientStatusLocked]. The delta-path equivalent is
// [LocalBackend.UpdateNetmapDelta], which routes peer
// adds/removes/patches through [nodeBackend.UpdateNetmapDelta] directly.
// This test pins down that the delta path stays subject to the tailnet
// lock filter: a fresh peer that ships as a [netmap.NodeMutationUpsert]
// must not reach [LocalBackend.NetMapWithPeers] without a verifying
// [tailcfg.Node.KeySignature].
//
// Updates #12542
// Updates tailscale/corp#43767
func TestTailnetLockFiltersUnsignedDeltaPeer(t *testing.T) {
	tstest.ResourceCheck(t)
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()

	// Trust an extra NL key the test holds so it can mint signed marker
	// peers for delta-sync below.
	markerNL := key.NewNLPrivate()
	s1, control, s1Key := setupTailnetLockedServer(t, ctx, tka.Key{
		Kind:   tka.Key25519,
		Public: markerNL.Public().Verifier(),
		Votes:  2,
	})

	// Build a fake peer Node with no KeySignature. testcontrol's normal
	// Node-registration path doesn't apply here -- we want a peer that
	// only ever exists as a PeersChanged delta entry, never as part of
	// a full netmap that would go through tkaFilterNetmapLocked.
	unsignedAddr := netip.MustParsePrefix("100.64.99.42/32")
	unsignedNode := &tailcfg.Node{
		ID:                tailcfg.NodeID(9999),
		StableID:          tailcfg.StableNodeID("TESTUNSIGNED0001"),
		Name:              "unsigned.test.",
		Key:               key.NewNode().Public(),
		Machine:           key.NewMachine().Public(),
		DiscoKey:          key.NewDisco().Public(),
		Addresses:         []netip.Prefix{unsignedAddr},
		AllowedIPs:        []netip.Prefix{unsignedAddr},
		MachineAuthorized: true,
		// KeySignature intentionally omitted: Tailnet Lock must drop this.
	}
	injectPeersChangedAndAssertFiltered(t, ctx, s1, control, s1Key, unsignedNode, markerNL)
}

// TestTailnetLockFiltersUnsignedDeltaPeerReplacement verifies that with
// Tailnet Lock enabled, replacing a previously-signed peer via
// [tailcfg.MapResponse.PeersChanged] with an unsigned copy causes that
// peer to drop from the local netmap, instead of lingering in
// [LocalBackend.NetMapWithPeers].
//
// This is structurally distinct from
// [TestTailnetLockFiltersUnsignedDeltaPeer] in that the peer already
// existed with a valid signature. The replacement strips the signature
// alongside a non-patchable field change ([tailcfg.Node.Name]) so that
// [mapSession.patchifyPeer] refuses to convert the entry to a
// [tailcfg.PeersChangedPatch] -- it stays in PeersChanged and reaches
// the local backend as a [netmap.NodeMutationUpsert], the same delta
// shape that
// [TestTailnetLockFiltersUnsignedDeltaPeer] exercises for an add but
// here applied to a swap-in of an unsigned replacement.
//
// Updates #12542
// Updates tailscale/corp#43767
func TestTailnetLockFiltersUnsignedDeltaPeerReplacement(t *testing.T) {
	tstest.ResourceCheck(t)
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()

	// Trust an extra NL key the test holds, so the test can mint valid
	// signatures for the fake peer without colluding with the node's
	// own NL private key (which lives only in s1's prefs).
	testNL := key.NewNLPrivate()
	s1, control, s1Key := setupTailnetLockedServer(t, ctx, tka.Key{
		Kind:   tka.Key25519,
		Public: testNL.Public().Verifier(),
		Votes:  2,
	})

	// Fake peer Node, signed by the test's extra trusted NL key.
	peerNodeKey := key.NewNode().Public()
	peerAddr := netip.MustParsePrefix("100.64.99.43/32")
	peerID := tailcfg.NodeID(9998)
	signedSig := signNodeKeyForTest(t, peerNodeKey, testNL)
	signedNode := &tailcfg.Node{
		ID:                peerID,
		StableID:          tailcfg.StableNodeID("TESTPEER00000001"),
		Name:              "peer.test.",
		Key:               peerNodeKey,
		Machine:           key.NewMachine().Public(),
		DiscoKey:          key.NewDisco().Public(),
		Addresses:         []netip.Prefix{peerAddr},
		AllowedIPs:        []netip.Prefix{peerAddr},
		MachineAuthorized: true,
		KeySignature:      signedSig,
	}

	// Inject the signed peer via PeersChanged, then wait for it to land
	// in s1's netmap with a valid KeySignature.
	if !control.AddRawMapResponse(s1Key, &tailcfg.MapResponse{
		PeersChanged: []*tailcfg.Node{signedNode},
	}) {
		t.Fatal("AddRawMapResponse(s1, signed peer): node not connected")
	}
	if err := waitFor(t, ctx, s1, func(nm *netmap.NetworkMap) bool {
		for _, p := range nm.Peers {
			if p.Key() == peerNodeKey && p.KeySignature().Len() > 0 {
				return true
			}
		}
		return false
	}); err != nil {
		t.Fatalf("waitFor signed peer to land in s1 netmap: %v", err)
	}

	// Now inject a replacement Node for the same peer ID with no
	// KeySignature and a non-patchable diff ([tailcfg.Node.Name]).
	// [mapSession.patchifyPeer] treats Name as an unpatchable field,
	// so the entry stays in [tailcfg.MapResponse.PeersChanged] and
	// reaches [LocalBackend.UpdateNetmapDelta] as a
	// [netmap.NodeMutationUpsert] of an unsigned Node, overwriting
	// the previously-signed [nodeBackend.peers] entry.
	replacement := signedNode.Clone()
	replacement.KeySignature = nil
	replacement.Name = "peer-renamed.test."
	injectPeersChangedAndAssertFiltered(t, ctx, s1, control, s1Key, replacement, testNL)
}

// TestTailnetLockFiltersDeltaPeerWithInvalidSignature verifies that with
// Tailnet Lock enabled, a peer arriving via
// [tailcfg.MapResponse.PeersChanged] with a non-empty but invalid
// [tailcfg.Node.KeySignature] is dropped from the local netmap.
//
// This is the verify-side counterpart to
// [TestTailnetLockFiltersUnsignedDeltaPeer], which covers the
// length-zero case: the same delta-path filter must also reject a
// signature blob that fails [tka.Authority.NodeKeyAuthorized] -- e.g.
// garbage bytes, a signature for a different node key, or a signature
// the local trust state doesn't accept.
//
// Updates #12542
// Updates tailscale/corp#43767
func TestTailnetLockFiltersDeltaPeerWithInvalidSignature(t *testing.T) {
	tstest.ResourceCheck(t)
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()

	testNL := key.NewNLPrivate()
	s1, control, s1Key := setupTailnetLockedServer(t, ctx, tka.Key{
		Kind:   tka.Key25519,
		Public: testNL.Public().Verifier(),
		Votes:  2,
	})

	// Construct a peer Node with a non-empty but unverifiable
	// KeySignature. The bytes are well-formed enough to round-trip
	// through JSON but [tka.NodeKeySignature.Unserialize] (called
	// from [tka.Authority.NodeKeyAuthorized]) will reject them.
	// That hits the verify-failure branch of
	// [LocalBackend.tkaFilterDeltaMutsLocked] rather than the
	// length-zero branch exercised by
	// [TestTailnetLockFiltersUnsignedDeltaPeer].
	badSigAddr := netip.MustParsePrefix("100.64.99.44/32")
	badSigNode := &tailcfg.Node{
		ID:                tailcfg.NodeID(9997),
		StableID:          tailcfg.StableNodeID("TESTBADSIG000001"),
		Name:              "badsig.test.",
		Key:               key.NewNode().Public(),
		Machine:           key.NewMachine().Public(),
		DiscoKey:          key.NewDisco().Public(),
		Addresses:         []netip.Prefix{badSigAddr},
		AllowedIPs:        []netip.Prefix{badSigAddr},
		MachineAuthorized: true,
		KeySignature:      []byte("not-a-real-tka-signature-just-garbage-bytes"),
	}
	injectPeersChangedAndAssertFiltered(t, ctx, s1, control, s1Key, badSigNode, testNL)
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
)

// TestWhoIsAfterPeerAddressReuse drives the whole client stack through the
// netmap delta ordering that broke WhoIs on App Connectors
// (tailscale/corp#47435).
//
// Control reassigns a churning ephemeral peer's Tailscale IP to a newer peer.
// The newer peer's upsert can reach the client before the older peer's
// removal, either in an earlier MapResponse or, as here, reordered within one
// MapResponse by the NodeID sort in netmap.MutationsFromMapResponse. Evicting
// the older peer's index entries unconditionally then wiped the address entry
// the newer peer had just claimed.
//
// n1 plays the App Connector. n2 plays the peer that ends up owning the
// address. n2 stays up throughout, so its WireGuard session with n1 keeps
// working while n1 can no longer say who owns its address.
//
// nodeBackend's own test covers the index bookkeeping directly. This test adds
// the two layers above it: that a MapResponse reusing an address is handled
// incrementally rather than as a full netmap, and that LocalBackend.WhoIs, the
// call PeerAPI makes before it accepts a connection, still resolves the
// address afterwards.
func TestWhoIsAfterPeerAddressReuse(t *testing.T) {
	tstest.Parallel(t)
	env := NewTestEnv(t)

	newNode := func() (*TestNode, key.NodePublic) {
		n := NewTestNode(t, env)
		n.StartDaemon()
		n.AwaitListening()
		n.MustUp()
		n.AwaitRunning()
		return n, n.MustStatus().Self.PublicKey
	}
	n1, k1 := newNode()
	n2, k2 := newNode()

	n1IP := n1.AwaitIP4()
	n2IP := n2.AwaitIP4()
	t.Logf("connector n1 = %v %v", k1.ShortString(), n1IP)
	t.Logf("peer      n2 = %v %v", k2.ShortString(), n2IP)

	// whoIsOwner reports which node key n1 believes owns n2's address. It runs
	// the same lookup peerAPIListener.ServeConn makes before accepting a
	// connection.
	whoIsOwner := func() (key.NodePublic, error) {
		who, err := n1.LocalClient().WhoIs(t.Context(), n2IP.String())
		if err != nil {
			return key.NodePublic{}, err
		}
		if who.Node == nil {
			return key.NodePublic{}, errors.New("nil Node")
		}
		if who.UserProfile == nil || who.UserProfile.ID == 0 {
			return key.NodePublic{}, fmt.Errorf("no user profile: %+v", who.UserProfile)
		}
		return who.Node.Key, nil
	}
	wantOwner := func(t *testing.T, want key.NodePublic, whose string) {
		t.Helper()
		got, err := whoIsOwner()
		if err != nil {
			t.Fatalf("n1 WhoIs(%v): %v; want %s", n2IP, err, whose)
		}
		if got != want {
			t.Fatalf("n1 WhoIs(%v) = %v; want %s %v", n2IP, got.ShortString(), whose, want.ShortString())
		}
	}
	awaitPeer := func(t *testing.T, k key.NodePublic, want bool) {
		t.Helper()
		if err := tstest.WaitFor(30*time.Second, func() error {
			_, ok := n1.MustStatus().Peer[k]
			if ok != want {
				return fmt.Errorf("n1 has peer %v = %v; want %v", k.ShortString(), ok, want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := tstest.WaitFor(30*time.Second, func() error {
		_, err := whoIsOwner()
		return err
	}); err != nil {
		t.Fatalf("baseline WhoIs(%v) on n1: %v", n2IP, err)
	}
	wantOwner(t, k2, "n2")
	t.Logf("baseline ok: n1 says %v owns %v", k2.ShortString(), n2IP)

	// oldOwner stands in for the ephemeral peer that held n2's address before
	// control reassigned it. Its user is n2's user, so the full netmap below
	// keeps carrying that user's profile. Without that, the netmap would also
	// drop the profile and WhoIs would fail for an unrelated reason.
	n2User := n2.MustStatus().Self.UserID
	oldOwner := &tailcfg.Node{
		ID:                12345,
		StableID:          "TESTOLDOWNER",
		Name:              "old-owner.fake-control.example.net.",
		User:              n2User,
		Key:               key.NewNode().Public(),
		Machine:           key.NewMachine().Public(),
		DiscoKey:          key.NewDisco().Public(),
		MachineAuthorized: true,
		Addresses:         []netip.Prefix{netip.PrefixFrom(n2IP, n2IP.BitLen())},
		AllowedIPs:        []netip.Prefix{netip.PrefixFrom(n2IP, n2IP.BitLen())},
	}

	// Step 1: a full netmap in which the address belongs to oldOwner. Setting
	// Peers makes the client treat this as a complete peer set, so it drops
	// n2. AddRawMapResponse also stops every later automatic map response to
	// n1, which is what keeps a full netmap from rebuilding n1's indexes
	// behind the test's back.
	if !env.Control.AddRawMapResponse(k1, &tailcfg.MapResponse{
		Peers: []*tailcfg.Node{oldOwner},
	}) {
		t.Fatal("AddRawMapResponse(full netmap) not delivered")
	}
	awaitPeer(t, k2, false)
	wantOwner(t, oldOwner.Key, "oldOwner")
	t.Logf("step 1: n1 says %v owns %v", oldOwner.Key.ShortString(), n2IP)

	// The node control hands back has to carry the disco key n2 is actually
	// using. A peer that arrives with a stale one makes n1 learn the current
	// key over TSMP, and that path rebuilds n1's whole netmap, which would
	// rebuild the indexes and hide the bug. n2 pushes its disco key on a
	// separate non-streaming poll, so wait for control to catch up.
	var n2node *tailcfg.Node
	if err := tstest.WaitFor(30*time.Second, func() error {
		want := selfDiscoKey(t, n2)
		n2node = env.Control.Node(k2)
		if n2node == nil {
			return errors.New("control has no node for n2")
		}
		if n2node.DiscoKey != want {
			return fmt.Errorf("control has disco key %v for n2; n2 is using %v",
				n2node.DiscoKey.ShortString(), want.ShortString())
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for control to learn n2's disco key: %v", err)
	}

	// Real control marks a connected node online, and that matters here.
	// removeUnwantedDiscoUpdates drops a TSMP-learned disco key for a peer
	// that is already online with that same key, and dropping it is what stops
	// the next WireGuard handshake from making n1 rebuild its full netmap.
	n2node.Online = new(true)
	n2node.LastSeen = new(time.Now())

	// Step 2: one MapResponse that hands the address to n2 and removes
	// oldOwner. MutationsFromMapResponse sorts by NodeID, and n2's ID is far
	// below oldOwner's, so the client applies n2's upsert first and then
	// oldOwner's removal. The removal must leave n2's claim on the address
	// alone.
	if !env.Control.AddRawMapResponse(k1, &tailcfg.MapResponse{
		PeersChanged: []*tailcfg.Node{n2node},
		PeersRemoved: []tailcfg.NodeID{oldOwner.ID},
	}) {
		t.Fatal("AddRawMapResponse(delta) not delivered")
	}
	awaitPeer(t, k2, true)
	t.Logf("step 2: n1 re-added n2 and removed oldOwner")

	// n1 must now name n2 as the owner of the address.
	wantOwner(t, k2, "n2")

	// And the data path has to still work, so a failure above is a failure to
	// identify a peer n1 is actively exchanging traffic with, not a peer it
	// has genuinely lost.
	if err := tstest.WaitFor(30*time.Second, func() error {
		out, err := n2.TailscaleForOutput("ping", "-c", "1", "--timeout=5s", "--tsmp", n1IP.String()).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	}); err != nil {
		t.Errorf("tsmp ping n2->n1: %v", err)
	}
	wantOwner(t, k2, "n2")
}

// selfDiscoKey returns the disco key n is currently advertising for itself.
func selfDiscoKey(t *testing.T, n *TestNode) key.DiscoPublic {
	t.Helper()
	out, err := n.TailscaleForOutput("debug", "netmap").Output()
	if err != nil {
		t.Fatalf("debug netmap: %v", err)
	}
	var nm struct {
		SelfNode struct {
			DiscoKey key.DiscoPublic
		}
	}
	if err := json.Unmarshal(out, &nm); err != nil {
		t.Fatalf("unmarshal netmap: %v", err)
	}
	return nm.SelfNode.DiscoKey
}

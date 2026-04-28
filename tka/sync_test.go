// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tstest"
	"tailscale.com/util/must"
)

func TestComputeSyncIntersection_FastForward(t *testing.T) {
	// Node 1 has: A1 -> A2
	// Node 2 has: A1 -> A2 -> A3 -> A4
	c := newTestchain(t, `
        A1 -> A2 -> A3 -> A4
    `)
	a1H, a2H := c.AUMHashes["A1"], c.AUMHashes["A2"]

	chonk1 := c.ChonkWith("A1", "A2")
	n1, err := Open(chonk1)
	if err != nil {
		t.Fatal(err)
	}
	offer1, err := n1.SyncOffer(chonk1)
	if err != nil {
		t.Fatal(err)
	}

	chonk2 := c.Chonk() // All AUMs
	n2, err := Open(chonk2)
	if err != nil {
		t.Fatal(err)
	}
	offer2, err := n2.SyncOffer(chonk2)
	if err != nil {
		t.Fatal(err)
	}

	// Node 1 only knows about the first two nodes, so the head of n2 is
	// alien to it.
	t.Run("n1", func(t *testing.T) {
		got, err := computeSyncIntersection(chonk1, offer1, offer2)
		if err != nil {
			t.Fatalf("computeSyncIntersection() failed: %v", err)
		}
		want := &intersection{
			tailIntersection: &a1H,
		}
		if diff := cmp.Diff(want, got, cmp.AllowUnexported(intersection{})); diff != "" {
			t.Errorf("intersection diff (-want, +got):\n%s", diff)
		}
	})

	// Node 2 knows about the full chain, so it can see that the head of n1
	// intersects with a subset of its chain (a Head Intersection).
	t.Run("n2", func(t *testing.T) {
		got, err := computeSyncIntersection(chonk2, offer2, offer1)
		if err != nil {
			t.Fatalf("computeSyncIntersection() failed: %v", err)
		}
		want := &intersection{
			headIntersection: &a2H,
		}
		if diff := cmp.Diff(want, got, cmp.AllowUnexported(intersection{})); diff != "" {
			t.Errorf("intersection diff (-want, +got):\n%s", diff)
		}
	})
}

func TestComputeSyncIntersection_ForkSmallDiff(t *testing.T) {
	// The number of nodes in the chain is longer than ancestorSkipStart,
	// so that during sync both nodes are able to find a common ancestor
	// which was later than A1.

	c := newTestchain(t, `
        A1 -> A2 -> A3 -> A4 -> A5 -> A6 -> A7 -> A8 -> A9 -> A10
                                                   | -> F1
        // Make F1 different to A9.
        // hashSeed is chosen such that the hash is higher than A9.
        F1.hashSeed = 7
    `)
	// Node 1 has: A1 -> A2 -> A3 -> A4 -> A5 -> A6 -> A7 -> A8 -> F1
	// Node 2 has: A1 -> A2 -> A3 -> A4 -> A5 -> A6 -> A7 -> A8 -> A9 -> A10
	f1H, a9H := c.AUMHashes["F1"], c.AUMHashes["A9"]

	if bytes.Compare(f1H[:], a9H[:]) < 0 {
		t.Fatal("failed assert: h(a9) > h(f1H)\nTweak hashSeed till this passes")
	}

	chonk1 := c.ChonkWith("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "F1")
	n1, err := Open(chonk1)
	if err != nil {
		t.Fatal(err)
	}
	offer1, err := n1.SyncOffer(chonk1)
	if err != nil {
		t.Fatal(err)
	}

	chonk2 := c.ChonkWith("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10")
	n2, err := Open(chonk2)
	if err != nil {
		t.Fatal(err)
	}
	offer2, err := n2.SyncOffer(chonk2)
	if err != nil {
		t.Fatal(err)
	}

	// Node 1 only knows about the first eight nodes, so the head of n2 is
	// alien to it.
	t.Run("n1", func(t *testing.T) {
		// n2 has 10 nodes, so the first common ancestor is the genesis AUM
		wantIntersection := c.AUMHashes["A1"]

		got, err := computeSyncIntersection(chonk1, offer1, offer2)
		if err != nil {
			t.Fatalf("computeSyncIntersection() failed: %v", err)
		}
		want := &intersection{
			tailIntersection: &wantIntersection,
		}
		if diff := cmp.Diff(want, got, cmp.AllowUnexported(intersection{})); diff != "" {
			t.Errorf("intersection diff (-want, +got):\n%s", diff)
		}
	})

	// Node 2 knows about the full chain but doesn't recognize the head.
	t.Run("n2", func(t *testing.T) {
		// n1 has 9 nodes, so the first common ancestor is the genesis AUM
		wantIntersection := c.AUMHashes["A1"]

		got, err := computeSyncIntersection(chonk2, offer2, offer1)
		if err != nil {
			t.Fatalf("computeSyncIntersection() failed: %v", err)
		}
		want := &intersection{
			tailIntersection: &wantIntersection,
		}
		if diff := cmp.Diff(want, got, cmp.AllowUnexported(intersection{})); diff != "" {
			t.Errorf("intersection diff (-want, +got):\n%s", diff)
		}
	})
}

func TestMissingAUMs_FastForward(t *testing.T) {
	// Node 1 has: A1 -> A2
	// Node 2 has: A1 -> A2 -> A3 -> A4
	c := newTestchain(t, `
        A1 -> A2 -> A3 -> A4
        A1.hashSeed = 1
        A2.hashSeed = 2
        A3.hashSeed = 3
        A4.hashSeed = 4
    `)

	chonk1 := c.ChonkWith("A1", "A2")
	n1, err := Open(chonk1)
	if err != nil {
		t.Fatal(err)
	}
	offer1, err := n1.SyncOffer(chonk1)
	if err != nil {
		t.Fatal(err)
	}

	chonk2 := c.Chonk() // All AUMs
	n2, err := Open(chonk2)
	if err != nil {
		t.Fatal(err)
	}
	offer2, err := n2.SyncOffer(chonk2)
	if err != nil {
		t.Fatal(err)
	}

	// Node 1 only knows about the first two nodes, so the head of n2 is
	// alien to it. As such, it should send history from the newest ancestor,
	// A1 (if the chain was longer there would be one in the middle).
	t.Run("n1", func(t *testing.T) {
		got, err := n1.MissingAUMs(chonk1, offer2)
		if err != nil {
			t.Fatalf("MissingAUMs() failed: %v", err)
		}

		// Both sides have A1, so the only AUM that n2 might not have is
		// A2.
		want := []AUM{c.AUMs["A2"]}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("MissingAUMs diff (-want, +got):\n%s", diff)
		}
	})

	// Node 2 knows about the full chain, so it can see that the head of n1
	// intersects with a subset of its chain (a Head Intersection).
	t.Run("n2", func(t *testing.T) {
		got, err := n2.MissingAUMs(chonk2, offer1)
		if err != nil {
			t.Fatalf("MissingAUMs() failed: %v", err)
		}

		want := []AUM{
			c.AUMs["A3"],
			c.AUMs["A4"],
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("MissingAUMs diff (-want, +got):\n%s", diff)
		}
	})
}

func TestMissingAUMs_Fork(t *testing.T) {
	// Node 1 has: A1 -> A2 -> A3 -> F1
	// Node 2 has: A1 -> A2 -> A3 -> A4
	c := newTestchain(t, `
        A1 -> A2 -> A3 -> A4
                     | -> F1
        A1.hashSeed = 1
        A2.hashSeed = 2
        A3.hashSeed = 3
        A4.hashSeed = 4
    `)

	chonk1 := c.ChonkWith("A1", "A2", "A3", "F1")
	n1, err := Open(chonk1)
	if err != nil {
		t.Fatal(err)
	}
	offer1, err := n1.SyncOffer(chonk1)
	if err != nil {
		t.Fatal(err)
	}

	chonk2 := c.ChonkWith("A1", "A2", "A3", "A4")
	n2, err := Open(chonk2)
	if err != nil {
		t.Fatal(err)
	}
	offer2, err := n2.SyncOffer(chonk2)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("n1", func(t *testing.T) {
		got, err := n1.MissingAUMs(chonk1, offer2)
		if err != nil {
			t.Fatalf("MissingAUMs() failed: %v", err)
		}

		// Both sides have A1, so n1 will send everything it knows from
		// there to head.
		want := []AUM{
			c.AUMs["A2"],
			c.AUMs["A3"],
			c.AUMs["F1"],
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("MissingAUMs diff (-want, +got):\n%s", diff)
		}
	})

	t.Run("n2", func(t *testing.T) {
		got, err := n2.MissingAUMs(chonk2, offer1)
		if err != nil {
			t.Fatalf("MissingAUMs() failed: %v", err)
		}

		// Both sides have A1, so n2 will send everything it knows from
		// there to head.
		want := []AUM{
			c.AUMs["A2"],
			c.AUMs["A3"],
			c.AUMs["A4"],
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("MissingAUMs diff (-want, +got):\n%s", diff)
		}
	})
}

func TestSyncSimpleE2E(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	c := newTestchain(t, `
        G1 -> L1 -> L2 -> L3
        G1.template = genesis
    `,
		optTemplate("genesis", AUM{MessageKind: AUMCheckpoint, State: &State{
			Keys:              []Key{key},
			DisablementValues: [][]byte{DisablementKDF([]byte{1, 2, 3})},
		}}),
		optKey("key", key, priv),
		optSignAllUsing("key"))

	nodeStorage := ChonkMem()
	node, err := Bootstrap(nodeStorage, c.AUMs["G1"])
	if err != nil {
		t.Fatalf("node Bootstrap() failed: %v", err)
	}
	controlStorage := c.Chonk()
	control, err := Open(controlStorage)
	if err != nil {
		t.Fatalf("control Open() failed: %v", err)
	}

	// Control knows the full chain, node only knows the genesis. Let's see
	// if they can sync.
	nodeOffer, err := node.SyncOffer(nodeStorage)
	if err != nil {
		t.Fatal(err)
	}
	controlAUMs, err := control.MissingAUMs(controlStorage, nodeOffer)
	if err != nil {
		t.Fatalf("control.MissingAUMs(%v) failed: %v", nodeOffer, err)
	}
	if err := node.Inform(nodeStorage, controlAUMs); err != nil {
		t.Fatalf("node.Inform(%v) failed: %v", controlAUMs, err)
	}

	if cHash, nHash := control.Head(), node.Head(); cHash != nHash {
		t.Errorf("node & control are not synced: c=%x, n=%x", cHash, nHash)
	}
}

// TestSyncFromFarBehind checks that nodes with compacted state can still find
// a common ancestor when the remote is significantly ahead.
//
// We simulate a node that has compacted its early history and is now ~500 AUMs
// behind the control plane, a distance that previously caused exponential sampling
// in SyncOffer to skip the node's entire local history.
//
// Regression test for http://go/corp/40404
func TestSyncFromFarBehind(t *testing.T) {
	pub1, priv1 := testingKey25519(t, 1)
	pub2, _ := testingKey25519(t, 2)
	signer1 := signer25519(priv1)

	key1 := Key{Kind: Key25519, Public: pub1, Votes: 2}
	key2 := Key{Kind: Key25519, Public: pub2, Votes: 2}

	// Setup: persistentAuthority (control plane) vs compactingAuthority (client node).
	state := State{
		Keys:              []Key{key1},
		DisablementValues: [][]byte{DisablementKDF([]byte{1, 2, 3})},
	}

	persistentStorage, compactingStorage := ChonkMem(), ChonkMem()
	persistentSize := func() int { return len(must.Get(persistentStorage.AllAUMs())) }
	compactingSize := func() int { return len(must.Get(compactingStorage.AllAUMs())) }

	// Backdate the clock on the compactingStorage so all AUMs will be old enough
	// to be considered for compacting.
	clock := tstest.NewClock(tstest.ClockOpts{
		Start: time.Now().Add(-(CompactionDefaults.MinAge + 24*time.Hour)),
	})
	compactingStorage.SetClock(clock)

	persistentAuthority, genesisAUM := must.Get2(Create(persistentStorage, state, signer1))
	compactingAuthority := must.Get(Bootstrap(compactingStorage, genesisAUM))

	// 1. Generate enough history to trigger checkpoints.
	for range checkpointEvery * 2 {
		update := persistentAuthority.NewUpdater(signer1)

		must.Do(update.AddKey(key2))
		addKey := must.Get(update.Finalize(persistentStorage))
		must.Do(persistentAuthority.Inform(persistentStorage, addKey))
		must.Do(compactingAuthority.Inform(compactingStorage, addKey))

		update = persistentAuthority.NewUpdater(signer1)
		must.Do(update.RemoveKey(key2.MustID()))
		removeKey := must.Get(update.Finalize(persistentStorage))
		must.Do(persistentAuthority.Inform(persistentStorage, removeKey))
		must.Do(compactingAuthority.Inform(compactingStorage, removeKey))
	}

	t.Logf("genesis and first batch of AUMs: persistent = %d, compacting = %d", persistentSize(), compactingSize())

	// 2. Compact the node state.
	//
	// It now has a different 'oldestAncestor' than the control plane.
	beforeCompacting := compactingSize()
	must.Do(compactingAuthority.Compact(compactingStorage, CompactionDefaults))
	afterCompacting := compactingSize()

	if beforeCompacting == afterCompacting {
		t.Errorf("expected Compact to reduce the number of AUMs, but unchanged: size = %d", afterCompacting)
	}

	// 3. Advance the control plane far beyond the node.
	//
	// As of 2026-04-17, the largest TKA has ~750 AUMs.
	//
	// If you keep increasing this number, eventually the sync will fail because you
	// hit the hard-coded limits on iteration during the sync process.
	for persistentSize() < compactingSize()+800 {
		b := persistentAuthority.NewUpdater(signer1)

		must.Do(b.AddKey(key2))
		addKey := must.Get(b.Finalize(persistentStorage))
		must.Do(persistentAuthority.Inform(persistentStorage, addKey))

		b = persistentAuthority.NewUpdater(signer1)
		must.Do(b.RemoveKey(key2.MustID()))
		removeKey := must.Get(b.Finalize(persistentStorage))
		must.Do(persistentAuthority.Inform(persistentStorage, removeKey))
	}

	t.Logf("post-compacting and extra AUMs:  persistent = %d, compacting = %d", persistentSize(), compactingSize())

	// 4. Verify Intersection.
	// The node should find an intersection even with a 500-AUM gap.
	persistentOffer := must.Get(persistentAuthority.SyncOffer(persistentStorage))
	compactingOffer := must.Get(compactingAuthority.SyncOffer(compactingStorage))

	if _, err := compactingAuthority.MissingAUMs(compactingStorage, persistentOffer); err != nil {
		t.Errorf("node failed to find intersection with far-ahead control plane: %v", err)
	}

	// 4. Check that the persistent authority can find an intersection with the
	// compacting authority, and has missing AUMs to send it.
	missing, err := persistentAuthority.MissingAUMs(persistentStorage, compactingOffer)
	if len(missing) == 0 {
		t.Errorf("control plane did not find any missing AUMs for node")
	}
	if err != nil {
		t.Errorf("control plane failed to find missing AUMs for node: %v", err)
	}
}

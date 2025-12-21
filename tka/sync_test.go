// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSyncOffer(t *testing.T) {
	c := newTestchain(t, `
        A1 -> A2 -> A3 -> A4 -> A5 -> A6 -> A7 -> A8 -> A9 -> A10
        A10 -> A11 -> A12 -> A13 -> A14 -> A15 -> A16 -> A17 -> A18
        A18 -> A19 -> A20 -> A21 -> A22 -> A23 -> A24 -> A25
    `)
	storage := c.Chonk()
	a, err := Open(storage)
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.SyncOffer(storage)
	if err != nil {
		t.Fatal(err)
	}

	// A SyncOffer includes a selection of AUMs going backwards in the tree,
	// progressively skipping more and more each iteration.
	want := SyncOffer{
		Head: c.AUMHashes["A25"],
		Ancestors: []AUMHash{
			c.AUMHashes["A"+strconv.Itoa(25-ancestorsSkipStart)],
			c.AUMHashes["A"+strconv.Itoa(25-ancestorsSkipStart<<ancestorsSkipShift)],
			c.AUMHashes["A1"],
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SyncOffer diff (-want, +got):\n%s", diff)
	}
}

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
	if diff := cmp.Diff(SyncOffer{
		Head: c.AUMHashes["F1"],
		Ancestors: []AUMHash{
			c.AUMHashes["A"+strconv.Itoa(9-ancestorsSkipStart)],
			c.AUMHashes["A1"],
		},
	}, offer1); diff != "" {
		t.Errorf("offer1 diff (-want, +got):\n%s", diff)
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
	if diff := cmp.Diff(SyncOffer{
		Head: c.AUMHashes["A10"],
		Ancestors: []AUMHash{
			c.AUMHashes["A"+strconv.Itoa(10-ancestorsSkipStart)],
			c.AUMHashes["A1"],
		},
	}, offer2); diff != "" {
		t.Errorf("offer2 diff (-want, +got):\n%s", diff)
	}

	// Node 1 only knows about the first eight nodes, so the head of n2 is
	// alien to it.
	t.Run("n1", func(t *testing.T) {
		// n2 has 10 nodes, so the first common ancestor should be 10-ancestorsSkipStart
		wantIntersection := c.AUMHashes["A"+strconv.Itoa(10-ancestorsSkipStart)]

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
		// n1 has 9 nodes, so the first common ancestor should be 9-ancestorsSkipStart
		wantIntersection := c.AUMHashes["A"+strconv.Itoa(9-ancestorsSkipStart)]

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
			Keys:               []Key{key},
			DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
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

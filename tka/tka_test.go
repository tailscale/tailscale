// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tka

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestComputeChainCandidates(t *testing.T) {
	c := newTestchain(t, `
        G1 -> I1 -> I2 -> I3 -> L2
               | -> L1     | -> L3
        
        G2 -> L4

        // We tweak these AUMs so they are different hashes.
        G2.hashSeed = 2
        L1.hashSeed = 2
        L3.hashSeed = 2
        L4.hashSeed = 3
    `)
	// Should result in 4 chains:
	// G1->L1, G1->L2, G1->L3, G2->L4

	i1H := c.AUMHashes["I1"]
	got, err := computeChainCandidates(c.Chonk(), &i1H, 50)
	if err != nil {
		t.Fatalf("computeChainCandidates() failed: %v", err)
	}

	want := []chain{
		{Oldest: c.AUMs["G1"], Head: c.AUMs["L1"], chainsThroughActive: true},
		{Oldest: c.AUMs["G1"], Head: c.AUMs["L3"], chainsThroughActive: true},
		{Oldest: c.AUMs["G1"], Head: c.AUMs["L2"], chainsThroughActive: true},
		{Oldest: c.AUMs["G2"], Head: c.AUMs["L4"]},
	}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(chain{})); diff != "" {
		t.Errorf("chains differ (-want, +got):\n%s", diff)
	}
}

func TestForkResolutionHash(t *testing.T) {
	c := newTestchain(t, `
        G1 -> L1
         | -> L2

        // tweak hashes so L1 & L2 are not identical
        L1.hashSeed = 2
        L2.hashSeed = 3
    `)

	got, err := computeActiveChain(c.Chonk(), nil, 50)
	if err != nil {
		t.Fatalf("computeActiveChain() failed: %v", err)
	}

	// The fork with the lowest AUM hash should have been chosen.
	l1H := c.AUMHashes["L1"]
	l2H := c.AUMHashes["L2"]
	want := l1H
	if bytes.Compare(l2H[:], l1H[:]) < 0 {
		want = l2H
	}

	if got := got.Head.Hash(); got != want {
		t.Errorf("head was %x, want %x", got, want)
	}
}

func TestForkResolutionSigWeight(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	c := newTestchain(t, `
        G1 -> L1
         | -> L2

        G1.template = addKey
        L1.hashSeed = 2
        L2.signedWith = key
    `,
		optTemplate("addKey", AUM{MessageKind: AUMAddKey, Key: &key}),
		optKey("key", key, priv))

	l1H := c.AUMHashes["L1"]
	l2H := c.AUMHashes["L2"]
	if bytes.Compare(l2H[:], l1H[:]) < 0 {
		t.Fatal("failed assert: h(l1) > h(l2)\nTweak hashSeed till this passes")
	}

	got, err := computeActiveChain(c.Chonk(), nil, 50)
	if err != nil {
		t.Fatalf("computeActiveChain() failed: %v", err)
	}

	// Based on the hash, l1H should be chosen.
	// But based on the signature weight (which has higher
	// precedence), it should be l2H
	want := l2H
	if got := got.Head.Hash(); got != want {
		t.Errorf("head was %x, want %x", got, want)
	}
}

func TestForkResolutionMessageType(t *testing.T) {
	pub, _ := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	c := newTestchain(t, `
        G1 -> L1
         | -> L2
         | -> L3

        G1.template = addKey
        L1.hashSeed = 11
        L2.template = removeKey
        L3.hashSeed = 18
    `,
		optTemplate("addKey", AUM{MessageKind: AUMAddKey, Key: &key}),
		optTemplate("removeKey", AUM{MessageKind: AUMRemoveKey, KeyID: key.ID()}))

	l1H := c.AUMHashes["L1"]
	l2H := c.AUMHashes["L2"]
	l3H := c.AUMHashes["L3"]
	if bytes.Compare(l2H[:], l1H[:]) < 0 {
		t.Fatal("failed assert: h(l1) > h(l2)\nTweak hashSeed till this passes")
	}
	if bytes.Compare(l2H[:], l3H[:]) < 0 {
		t.Fatal("failed assert: h(l3) > h(l2)\nTweak hashSeed till this passes")
	}

	got, err := computeActiveChain(c.Chonk(), nil, 50)
	if err != nil {
		t.Fatalf("computeActiveChain() failed: %v", err)
	}

	// Based on the hash, L1 or L3 should be chosen.
	// But based on the preference for AUMRemoveKey messages,
	// it should be L2.
	want := l2H
	if got := got.Head.Hash(); got != want {
		t.Errorf("head was %x, want %x", got, want)
	}
}

func TestComputeStateAt(t *testing.T) {
	pub, _ := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	c := newTestchain(t, `
        G1 -> I1 -> I2
        I1.template = addKey
    `,
		optTemplate("addKey", AUM{MessageKind: AUMAddKey, Key: &key}))

	// G1 is before the key, so there shouldn't be a key there.
	state, err := computeStateAt(c.Chonk(), 500, c.AUMHashes["G1"])
	if err != nil {
		t.Fatalf("computeStateAt(G1) failed: %v", err)
	}
	if _, err := state.GetKey(key.ID()); err != ErrNoSuchKey {
		t.Errorf("expected key to be missing: err = %v", err)
	}
	if *state.LastAUMHash != c.AUMHashes["G1"] {
		t.Errorf("LastAUMHash = %x, want %x", *state.LastAUMHash, c.AUMHashes["G1"])
	}

	// I1 & I2 are after the key, so the computed state should contain
	// the key.
	for _, wantHash := range []AUMHash{c.AUMHashes["I1"], c.AUMHashes["I2"]} {
		state, err = computeStateAt(c.Chonk(), 500, wantHash)
		if err != nil {
			t.Fatalf("computeStateAt(%X) failed: %v", wantHash, err)
		}
		if *state.LastAUMHash != wantHash {
			t.Errorf("LastAUMHash = %x, want %x", *state.LastAUMHash, wantHash)
		}
		if _, err := state.GetKey(key.ID()); err != nil {
			t.Errorf("expected key to be present at state: err = %v", err)
		}
	}
}

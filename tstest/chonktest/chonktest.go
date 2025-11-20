// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package chonktest contains a shared set of tests for the Chonk
// interface used to store AUM messages in Tailnet Lock, which we can
// share between different implementations.
package chonktest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/crypto/blake2s"
	"tailscale.com/tka"
	"tailscale.com/util/must"
)

// returns a random source based on the test name + extraSeed.
func testingRand(t *testing.T, extraSeed int64) *rand.Rand {
	var seed int64
	if err := binary.Read(bytes.NewBuffer([]byte(t.Name())), binary.LittleEndian, &seed); err != nil {
		panic(err)
	}
	return rand.New(rand.NewSource(seed + extraSeed))
}

// randHash derives a fake blake2s hash from the test name
// and the given seed.
func randHash(t *testing.T, seed int64) [blake2s.Size]byte {
	var out [blake2s.Size]byte
	testingRand(t, seed).Read(out[:])
	return out
}

func hashesLess(x, y tka.AUMHash) bool {
	return bytes.Compare(x[:], y[:]) < 0
}

func aumHashesLess(x, y tka.AUM) bool {
	return hashesLess(x.Hash(), y.Hash())
}

// RunChonkTests is a set of tests for the behaviour of a Chonk.
//
// Any implementation of Chonk should pass these tests, so we know all
// Chonks behave in the same way. If you want to test behaviour that's
// specific to one implementation, write a separate test.
func RunChonkTests(t *testing.T, newChonk func(*testing.T) tka.Chonk) {
	t.Run("ChildAUMs", func(t *testing.T) {
		t.Parallel()
		chonk := newChonk(t)
		parentHash := randHash(t, 1)
		data := []tka.AUM{
			{
				MessageKind: tka.AUMRemoveKey,
				KeyID:       []byte{1, 2},
				PrevAUMHash: parentHash[:],
			},
			{
				MessageKind: tka.AUMRemoveKey,
				KeyID:       []byte{3, 4},
				PrevAUMHash: parentHash[:],
			},
		}

		if err := chonk.CommitVerifiedAUMs(data); err != nil {
			t.Fatalf("CommitVerifiedAUMs failed: %v", err)
		}
		stored, err := chonk.ChildAUMs(parentHash)
		if err != nil {
			t.Fatalf("ChildAUMs failed: %v", err)
		}
		if diff := cmp.Diff(data, stored, cmpopts.SortSlices(aumHashesLess)); diff != "" {
			t.Errorf("stored AUM differs (-want, +got):\n%s", diff)
		}
	})

	t.Run("AUMMissing", func(t *testing.T) {
		t.Parallel()
		chonk := newChonk(t)
		var notExists tka.AUMHash
		notExists[:][0] = 42
		if _, err := chonk.AUM(notExists); err != os.ErrNotExist {
			t.Errorf("chonk.AUM(notExists).err = %v, want %v", err, os.ErrNotExist)
		}
	})

	t.Run("ReadChainFromHead", func(t *testing.T) {
		t.Parallel()
		chonk := newChonk(t)
		genesis := tka.AUM{MessageKind: tka.AUMRemoveKey, KeyID: []byte{1, 2}}
		gHash := genesis.Hash()
		intermediate := tka.AUM{PrevAUMHash: gHash[:]}
		iHash := intermediate.Hash()
		leaf := tka.AUM{PrevAUMHash: iHash[:]}

		commitSet := []tka.AUM{
			genesis,
			intermediate,
			leaf,
		}
		if err := chonk.CommitVerifiedAUMs(commitSet); err != nil {
			t.Fatalf("CommitVerifiedAUMs failed: %v", err)
		}
		t.Logf("genesis hash = %X", genesis.Hash())
		t.Logf("intermediate hash = %X", intermediate.Hash())
		t.Logf("leaf hash = %X", leaf.Hash())

		// Read the chain from the leaf backwards.
		gotLeafs, err := chonk.Heads()
		if err != nil {
			t.Fatalf("Heads failed: %v", err)
		}
		if diff := cmp.Diff([]tka.AUM{leaf}, gotLeafs); diff != "" {
			t.Fatalf("leaf AUM differs (-want, +got):\n%s", diff)
		}

		parent, _ := gotLeafs[0].Parent()
		gotIntermediate, err := chonk.AUM(parent)
		if err != nil {
			t.Fatalf("AUM(<intermediate>) failed: %v", err)
		}
		if diff := cmp.Diff(intermediate, gotIntermediate); diff != "" {
			t.Errorf("intermediate AUM differs (-want, +got):\n%s", diff)
		}

		parent, _ = gotIntermediate.Parent()
		gotGenesis, err := chonk.AUM(parent)
		if err != nil {
			t.Fatalf("AUM(<genesis>) failed: %v", err)
		}
		if diff := cmp.Diff(genesis, gotGenesis); diff != "" {
			t.Errorf("genesis AUM differs (-want, +got):\n%s", diff)
		}
	})

	t.Run("LastActiveAncestor", func(t *testing.T) {
		t.Parallel()
		chonk := newChonk(t)

		aum := tka.AUM{MessageKind: tka.AUMRemoveKey, KeyID: []byte{1, 2}}
		hash := aum.Hash()

		if err := chonk.SetLastActiveAncestor(hash); err != nil {
			t.Fatal(err)
		}
		got, err := chonk.LastActiveAncestor()
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || hash.String() != got.String() {
			t.Errorf("LastActiveAncestor=%s, want %s", got, hash)
		}
	})
}

// RunCompactableChonkTests is a set of tests for the behaviour of a
// CompactableChonk.
//
// Any implementation of CompactableChonk should pass these tests, so we
// know all CompactableChonk behave in the same way. If you want to test
// behaviour that's specific to one implementation, write a separate test.
func RunCompactableChonkTests(t *testing.T, newChonk func(t *testing.T) tka.CompactableChonk) {
	t.Run("PurgeAUMs", func(t *testing.T) {
		t.Parallel()
		chonk := newChonk(t)
		parentHash := randHash(t, 1)
		aum := tka.AUM{MessageKind: tka.AUMNoOp, PrevAUMHash: parentHash[:]}

		if err := chonk.CommitVerifiedAUMs([]tka.AUM{aum}); err != nil {
			t.Fatal(err)
		}
		if err := chonk.PurgeAUMs([]tka.AUMHash{aum.Hash()}); err != nil {
			t.Fatal(err)
		}

		if _, err := chonk.AUM(aum.Hash()); err != os.ErrNotExist {
			t.Errorf("AUM() on purged AUM returned err = %v, want ErrNotExist", err)
		}
	})

	t.Run("AllAUMs", func(t *testing.T) {
		chonk := newChonk(t)
		genesis := tka.AUM{MessageKind: tka.AUMRemoveKey, KeyID: []byte{1, 2}}
		gHash := genesis.Hash()
		intermediate := tka.AUM{PrevAUMHash: gHash[:]}
		iHash := intermediate.Hash()
		leaf := tka.AUM{PrevAUMHash: iHash[:]}

		commitSet := []tka.AUM{
			genesis,
			intermediate,
			leaf,
		}
		if err := chonk.CommitVerifiedAUMs(commitSet); err != nil {
			t.Fatalf("CommitVerifiedAUMs failed: %v", err)
		}

		hashes, err := chonk.AllAUMs()
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]tka.AUMHash{genesis.Hash(), intermediate.Hash(), leaf.Hash()}, hashes, cmpopts.SortSlices(hashesLess)); diff != "" {
			t.Fatalf("AllAUMs() output differs (-want, +got):\n%s", diff)
		}
	})

	t.Run("ChildAUMsOfPurgedAUM", func(t *testing.T) {
		t.Parallel()
		chonk := newChonk(t)
		parent := tka.AUM{MessageKind: tka.AUMRemoveKey, KeyID: []byte{0, 0}}

		parentHash := parent.Hash()

		child1 := tka.AUM{MessageKind: tka.AUMAddKey, KeyID: []byte{1, 1}, PrevAUMHash: parentHash[:]}
		child2 := tka.AUM{MessageKind: tka.AUMAddKey, KeyID: []byte{2, 2}, PrevAUMHash: parentHash[:]}
		child3 := tka.AUM{MessageKind: tka.AUMAddKey, KeyID: []byte{3, 3}, PrevAUMHash: parentHash[:]}

		child2Hash := child2.Hash()
		grandchild2A := tka.AUM{MessageKind: tka.AUMAddKey, KeyID: []byte{2, 2, 2, 2}, PrevAUMHash: child2Hash[:]}
		grandchild2B := tka.AUM{MessageKind: tka.AUMAddKey, KeyID: []byte{2, 2, 2, 2, 2}, PrevAUMHash: child2Hash[:]}

		commitSet := []tka.AUM{parent, child1, child2, child3, grandchild2A, grandchild2B}

		if err := chonk.CommitVerifiedAUMs(commitSet); err != nil {
			t.Fatalf("CommitVerifiedAUMs failed: %v", err)
		}

		// Check the set of hashes is correct
		childHashes := must.Get(chonk.ChildAUMs(parentHash))
		if diff := cmp.Diff([]tka.AUM{child1, child2, child3}, childHashes, cmpopts.SortSlices(aumHashesLess)); diff != "" {
			t.Fatalf("ChildAUMs() output differs (-want, +got):\n%s", diff)
		}

		// Purge the parent AUM, and check the set of child AUMs is unchanged
		chonk.PurgeAUMs([]tka.AUMHash{parent.Hash()})

		childHashes = must.Get(chonk.ChildAUMs(parentHash))
		if diff := cmp.Diff([]tka.AUM{child1, child2, child3}, childHashes, cmpopts.SortSlices(aumHashesLess)); diff != "" {
			t.Fatalf("ChildAUMs() output differs (-want, +got):\n%s", diff)
		}

		// Now purge one of the child AUMs, and check it no longer appears as a child of the parent
		chonk.PurgeAUMs([]tka.AUMHash{child3.Hash()})

		childHashes = must.Get(chonk.ChildAUMs(parentHash))
		if diff := cmp.Diff([]tka.AUM{child1, child2}, childHashes, cmpopts.SortSlices(aumHashesLess)); diff != "" {
			t.Fatalf("ChildAUMs() output differs (-want, +got):\n%s", diff)
		}
	})

	t.Run("RemoveAll", func(t *testing.T) {
		t.Parallel()
		chonk := newChonk(t)
		parentHash := randHash(t, 1)
		data := []tka.AUM{
			{
				MessageKind: tka.AUMRemoveKey,
				KeyID:       []byte{1, 2},
				PrevAUMHash: parentHash[:],
			},
			{
				MessageKind: tka.AUMRemoveKey,
				KeyID:       []byte{3, 4},
				PrevAUMHash: parentHash[:],
			},
		}

		if err := chonk.CommitVerifiedAUMs(data); err != nil {
			t.Fatalf("CommitVerifiedAUMs failed: %v", err)
		}

		// Check we can retrieve the AUMs we just stored
		for _, want := range data {
			got, err := chonk.AUM(want.Hash())
			if err != nil {
				t.Fatalf("could not get %s: %v", want.Hash(), err)
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("stored AUM %s differs (-want, +got):\n%s", want.Hash(), diff)
			}
		}

		// Call RemoveAll() to drop all the AUM state
		if err := chonk.RemoveAll(); err != nil {
			t.Fatalf("RemoveAll failed: %v", err)
		}

		// Check we can no longer retrieve the previously-stored AUMs
		for _, want := range data {
			aum, err := chonk.AUM(want.Hash())
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected os.ErrNotExist for %s, instead got aum=%v, err=%v", want.Hash(), aum, err)
			}
		}
	})
}

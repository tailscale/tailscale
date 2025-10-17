// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package tka

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/crypto/blake2s"
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

func hashesLess(x, y AUMHash) bool {
	return bytes.Compare(x[:], y[:]) < 0
}

func aumHashesLess(x, y AUM) bool {
	return hashesLess(x.Hash(), y.Hash())
}

func RunChonkTests(t *testing.T, newChonk func(t *testing.T) Chonk) {
	t.Run("ChildAUMs", func(t *testing.T) {
		t.Parallel()
		chonk := newChonk(t)
		parentHash := randHash(t, 1)
		data := []AUM{
			{
				MessageKind: AUMRemoveKey,
				KeyID:       []byte{1, 2},
				PrevAUMHash: parentHash[:],
			},
			{
				MessageKind: AUMRemoveKey,
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
		var notExists AUMHash
		notExists[:][0] = 42
		if _, err := chonk.AUM(notExists); err != os.ErrNotExist {
			t.Errorf("chonk.AUM(notExists).err = %v, want %v", err, os.ErrNotExist)
		}
	})

	t.Run("ReadChainFromHead", func(t *testing.T) {
		t.Parallel()
		chonk := newChonk(t)
		genesis := AUM{MessageKind: AUMRemoveKey, KeyID: []byte{1, 2}}
		gHash := genesis.Hash()
		intermediate := AUM{PrevAUMHash: gHash[:]}
		iHash := intermediate.Hash()
		leaf := AUM{PrevAUMHash: iHash[:]}

		commitSet := []AUM{
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
		if diff := cmp.Diff([]AUM{leaf}, gotLeafs); diff != "" {
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

		aum := AUM{MessageKind: AUMRemoveKey, KeyID: []byte{1, 2}}
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

func RunCompactableChonkTests(t *testing.T, newChonk func(t *testing.T) CompactableChonk) {
	t.Run("PurgeAUMs", func(t *testing.T) {
		t.Parallel()
		chonk := newChonk(t)
		parentHash := randHash(t, 1)
		aum := AUM{MessageKind: AUMNoOp, PrevAUMHash: parentHash[:]}

		if err := chonk.CommitVerifiedAUMs([]AUM{aum}); err != nil {
			t.Fatal(err)
		}
		if err := chonk.PurgeAUMs([]AUMHash{aum.Hash()}); err != nil {
			t.Fatal(err)
		}

		if _, err := chonk.AUM(aum.Hash()); err != os.ErrNotExist {
			t.Errorf("AUM() on purged AUM returned err = %v, want ErrNotExist", err)
		}
	})

	t.Run("AllAUMs", func(t *testing.T) {
		chonk := newChonk(t)
		genesis := AUM{MessageKind: AUMRemoveKey, KeyID: []byte{1, 2}}
		gHash := genesis.Hash()
		intermediate := AUM{PrevAUMHash: gHash[:]}
		iHash := intermediate.Hash()
		leaf := AUM{PrevAUMHash: iHash[:]}

		commitSet := []AUM{
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
		if diff := cmp.Diff([]AUMHash{genesis.Hash(), intermediate.Hash(), leaf.Hash()}, hashes, cmpopts.SortSlices(hashesLess)); diff != "" {
			t.Fatalf("AllAUMs() output differs (-want, +got):\n%s", diff)
		}
	})

	t.Run("ChildAUMsOfPurgedAUM", func(t *testing.T) {
		t.Parallel()
		chonk := newChonk(t)
		parent := AUM{MessageKind: AUMRemoveKey, KeyID: []byte{0, 0}}

		parentHash := parent.Hash()

		child1 := AUM{MessageKind: AUMAddKey, KeyID: []byte{1, 1}, PrevAUMHash: parentHash[:]}
		child2 := AUM{MessageKind: AUMAddKey, KeyID: []byte{2, 2}, PrevAUMHash: parentHash[:]}
		child3 := AUM{MessageKind: AUMAddKey, KeyID: []byte{3, 3}, PrevAUMHash: parentHash[:]}

		child2Hash := child2.Hash()
		grandchild2A := AUM{MessageKind: AUMAddKey, KeyID: []byte{2, 2, 2, 2}, PrevAUMHash: child2Hash[:]}
		grandchild2B := AUM{MessageKind: AUMAddKey, KeyID: []byte{2, 2, 2, 2, 2}, PrevAUMHash: child2Hash[:]}

		commitSet := []AUM{parent, child1, child2, child3, grandchild2A, grandchild2B}

		if err := chonk.CommitVerifiedAUMs(commitSet); err != nil {
			t.Fatalf("CommitVerifiedAUMs failed: %v", err)
		}

		// Check the set of hashes is correct
		childHashes := must.Get(chonk.ChildAUMs(parentHash))
		if diff := cmp.Diff([]AUM{child1, child2, child3}, childHashes, cmpopts.SortSlices(aumHashesLess)); diff != "" {
			t.Fatalf("ChildAUMs() output differs (-want, +got):\n%s", diff)
		}

		// Purge the parent AUM, and check the set of child AUMs is unchanged
		chonk.PurgeAUMs([]AUMHash{parent.Hash()})

		childHashes = must.Get(chonk.ChildAUMs(parentHash))
		if diff := cmp.Diff([]AUM{child1, child2, child3}, childHashes, cmpopts.SortSlices(aumHashesLess)); diff != "" {
			t.Fatalf("ChildAUMs() output differs (-want, +got):\n%s", diff)
		}

		// Now purge one of the child AUMs, and check it no longer appears as a child of the parent
		chonk.PurgeAUMs([]AUMHash{child3.Hash()})

		childHashes = must.Get(chonk.ChildAUMs(parentHash))
		if diff := cmp.Diff([]AUM{child1, child2}, childHashes, cmpopts.SortSlices(aumHashesLess)); diff != "" {
			t.Fatalf("ChildAUMs() output differs (-want, +got):\n%s", diff)
		}
	})
}

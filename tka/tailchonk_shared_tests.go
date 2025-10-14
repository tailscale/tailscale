// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/blake2s"
)

// returns a random source based on the test name + extraSeed.
func testingRand(t *testing.T, extraSeed int64) *rand.Rand {
	var seed int64
	if err := binary.Read(bytes.NewBuffer([]byte(t.Name())), binary.LittleEndian, &seed); err != nil {
		panic(err)
	}
	return rand.New(rand.NewSource(seed + extraSeed))
}

func randHash(t *testing.T, seed int64) [blake2s.Size]byte {
	var out [blake2s.Size]byte
	testingRand(t, seed).Read(out[:])
	return out
}

func TestChonkImplementation(t *testing.T, createChonk func(t *testing.T) Chonk) {
	t.Run("ChildAUMs", func(t *testing.T) {
		chonk := createChonk(t)
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
		if diff := cmp.Diff(data, stored); diff != "" {
			t.Errorf("stored AUM differs (-want, +got):\n%s", diff)
		}
	})

	t.Run("AUMMissing", func(t *testing.T) {
		chonk := createChonk(t)
		var notExists AUMHash
		notExists[:][0] = 42
		if _, err := chonk.AUM(notExists); err != os.ErrNotExist {
			t.Errorf("chonk.AUM(notExists).err = %v, want %v", err, os.ErrNotExist)
		}
	})

	t.Run("ReadChainFromHead", func(t *testing.T) {
		chonk := createChonk(t)
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
		// t.Logf("genesis hash = %X", genesis.Hash())
		// t.Logf("intermediate hash = %X", intermediate.Hash())
		// t.Logf("leaf hash = %X", leaf.Hash())

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
		chonk := createChonk(t)
		t.Parallel()

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

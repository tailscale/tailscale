// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tka

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/blake2s"
)

// randHash derives a fake blake2s hash from the test name
// and the given seed.
func randHash(t *testing.T, seed int64) [blake2s.Size]byte {
	var out [blake2s.Size]byte
	testingRand(t, seed).Read(out[:])
	return out
}

func TestImplementsChonk(t *testing.T) {
	impls := []Chonk{&Mem{}, &FS{}}
	t.Logf("chonks: %v", impls)
}

func TestTailchonk_ChildAUMs(t *testing.T) {
	for _, chonk := range []Chonk{&Mem{}, &FS{base: t.TempDir()}} {
		t.Run(fmt.Sprintf("%T", chonk), func(t *testing.T) {
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
	}
}

func TestTailchonk_AUMMissing(t *testing.T) {
	for _, chonk := range []Chonk{&Mem{}, &FS{base: t.TempDir()}} {
		t.Run(fmt.Sprintf("%T", chonk), func(t *testing.T) {
			var notExists AUMHash
			notExists[:][0] = 42
			if _, err := chonk.AUM(notExists); err != os.ErrNotExist {
				t.Errorf("chonk.AUM(notExists).err = %v, want %v", err, os.ErrNotExist)
			}
		})
	}
}

func TestTailchonkMem_Orphans(t *testing.T) {
	chonk := Mem{}

	parentHash := randHash(t, 1)
	orphan := AUM{MessageKind: AUMNoOp}
	aums := []AUM{
		orphan,
		// A parent is specified, so we shouldnt see it in GetOrphans()
		{
			MessageKind: AUMRemoveKey,
			KeyID:       []byte{3, 4},
			PrevAUMHash: parentHash[:],
		},
	}
	if err := chonk.CommitVerifiedAUMs(aums); err != nil {
		t.Fatalf("CommitVerifiedAUMs failed: %v", err)
	}

	stored, err := chonk.Orphans()
	if err != nil {
		t.Fatalf("Orphans failed: %v", err)
	}
	if diff := cmp.Diff([]AUM{orphan}, stored); diff != "" {
		t.Errorf("stored AUM differs (-want, +got):\n%s", diff)
	}
}

func TestTailchonk_ReadChainFromHead(t *testing.T) {
	for _, chonk := range []Chonk{&Mem{}, &FS{base: t.TempDir()}} {

		t.Run(fmt.Sprintf("%T", chonk), func(t *testing.T) {
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
	}
}

func TestTailchonkFS_Commit(t *testing.T) {
	chonk := &FS{base: t.TempDir()}
	parentHash := randHash(t, 1)
	aum := AUM{MessageKind: AUMNoOp, PrevAUMHash: parentHash[:]}

	if err := chonk.CommitVerifiedAUMs([]AUM{aum}); err != nil {
		t.Fatal(err)
	}

	dir, base := chonk.aumDir(aum.Hash())
	if got, want := dir, filepath.Join(chonk.base, "PD"); got != want {
		t.Errorf("aum dir=%s, want %s", got, want)
	}
	if want := "PD57DVP6GKC76OOZMXFFZUSOEFQXOLAVT7N2ZM5KB3HDIMCANF4A"; base != want {
		t.Errorf("aum base=%s, want %s", base, want)
	}
	if _, err := os.Stat(filepath.Join(dir, base)); err != nil {
		t.Errorf("stat of AUM file failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(chonk.base, "M7", "M7LL2NDB4NKCZIUPVS6RDM2GUOIMW6EEAFVBWMVCPUANQJPHT3SQ")); err != nil {
		t.Errorf("stat of AUM parent failed: %v", err)
	}
}

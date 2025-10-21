// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/crypto/blake2s"
	"tailscale.com/util/must"
)

// This package has implementation-specific tests for Mem and FS.
//
// We also have tests for the Chonk interface in `chonktest`, which exercises
// both Mem and FS. Those tests are in a separate package so they can be shared
// with other repos; we don't call the shared test helpers from this package
// to avoid creating a circular dependency.

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

func TestTailchonkFS_Commit(t *testing.T) {
	chonk := must.Get(ChonkDir(t.TempDir()))
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

	info, err := chonk.get(aum.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if info.PurgedUnix > 0 {
		t.Errorf("recently-created AUM PurgedUnix = %d, want 0", info.PurgedUnix)
	}
}

func TestTailchonkFS_CommitTime(t *testing.T) {
	chonk := must.Get(ChonkDir(t.TempDir()))
	parentHash := randHash(t, 1)
	aum := AUM{MessageKind: AUMNoOp, PrevAUMHash: parentHash[:]}

	if err := chonk.CommitVerifiedAUMs([]AUM{aum}); err != nil {
		t.Fatal(err)
	}
	ct, err := chonk.CommitTime(aum.Hash())
	if err != nil {
		t.Fatalf("CommitTime() failed: %v", err)
	}
	if ct.Before(time.Now().Add(-time.Minute)) || ct.After(time.Now().Add(time.Minute)) {
		t.Errorf("commit time was wrong: %v more than a minute off from now (%v)", ct, time.Now())
	}
}

// If we were interrupted while writing a temporary file, AllAUMs()
// should ignore it when scanning the AUM directory.
func TestTailchonkFS_IgnoreTempFile(t *testing.T) {
	base := t.TempDir()
	chonk := must.Get(ChonkDir(base))
	parentHash := randHash(t, 1)
	aum := AUM{MessageKind: AUMNoOp, PrevAUMHash: parentHash[:]}
	must.Do(chonk.CommitVerifiedAUMs([]AUM{aum}))

	writeAUMFile := func(filename, contents string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(base, filename[0:2]), os.ModePerm); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, filename[0:2], filename), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Check that calling AllAUMs() returns the single committed AUM
	got, err := chonk.AllAUMs()
	if err != nil {
		t.Fatalf("AllAUMs() failed: %v", err)
	}
	want := []AUMHash{aum.Hash()}
	if !slices.Equal(got, want) {
		t.Fatalf("AllAUMs() is wrong: got %v, want %v", got, want)
	}

	// Write some temporary files which are named like partially-committed AUMs,
	// then check that AllAUMs() only returns the single committed AUM.
	writeAUMFile("AUM1234.tmp", "incomplete AUM\n")
	writeAUMFile("AUM1234.tmp_123", "second incomplete AUM\n")

	got, err = chonk.AllAUMs()
	if err != nil {
		t.Fatalf("AllAUMs() failed: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("AllAUMs() is wrong: got %v, want %v", got, want)
	}
}

func TestMarkActiveChain(t *testing.T) {
	type aumTemplate struct {
		AUM AUM
	}

	tcs := []struct {
		name                string
		minChain            int
		chain               []aumTemplate
		expectLastActiveIdx int // expected lastActiveAncestor, corresponds to an index on chain.
	}{
		{
			name:     "genesis",
			minChain: 2,
			chain: []aumTemplate{
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
			},
			expectLastActiveIdx: 0,
		},
		{
			name:     "simple truncate",
			minChain: 2,
			chain: []aumTemplate{
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
			},
			expectLastActiveIdx: 1,
		},
		{
			name:     "long truncate",
			minChain: 5,
			chain: []aumTemplate{
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
			},
			expectLastActiveIdx: 2,
		},
		{
			name:     "truncate finding checkpoint",
			minChain: 2,
			chain: []aumTemplate{
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMAddKey, Key: &Key{}}}, // Should keep searching upwards for a checkpoint
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
			},
			expectLastActiveIdx: 1,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			verdict := make(map[AUMHash]retainState, len(tc.chain))

			// Build the state of the tailchonk for tests.
			storage := &Mem{}
			var prev AUMHash
			for i := range tc.chain {
				if !prev.IsZero() {
					tc.chain[i].AUM.PrevAUMHash = make([]byte, len(prev[:]))
					copy(tc.chain[i].AUM.PrevAUMHash, prev[:])
				}
				if err := storage.CommitVerifiedAUMs([]AUM{tc.chain[i].AUM}); err != nil {
					t.Fatal(err)
				}

				h := tc.chain[i].AUM.Hash()
				prev = h
				verdict[h] = 0
			}

			got, err := markActiveChain(storage, verdict, tc.minChain, prev)
			if err != nil {
				t.Logf("state = %+v", verdict)
				t.Fatalf("markActiveChain() failed: %v", err)
			}
			want := tc.chain[tc.expectLastActiveIdx].AUM.Hash()
			if got != want {
				t.Logf("state = %+v", verdict)
				t.Errorf("lastActiveAncestor = %v, want %v", got, want)
			}

			// Make sure the verdict array was marked correctly.
			for i := range tc.chain {
				h := tc.chain[i].AUM.Hash()
				if i >= tc.expectLastActiveIdx {
					if (verdict[h] & retainStateActive) == 0 {
						t.Errorf("verdict[%v] = %v, want %v set", h, verdict[h], retainStateActive)
					}
				} else {
					if (verdict[h] & retainStateCandidate) == 0 {
						t.Errorf("verdict[%v] = %v, want %v set", h, verdict[h], retainStateCandidate)
					}
				}
			}
		})
	}
}

func TestMarkDescendantAUMs(t *testing.T) {
	c := newTestchain(t, `
        genesis -> B -> C -> C2
                   | -> D
                   | -> E -> F -> G -> H
                        | -> E2

        // tweak seeds so hashes arent identical
        C.hashSeed = 1
        D.hashSeed = 2
        E.hashSeed = 3
        E2.hashSeed = 4
    `)

	verdict := make(map[AUMHash]retainState, len(c.AUMs))
	for _, a := range c.AUMs {
		verdict[a.Hash()] = 0
	}

	// Mark E & C.
	verdict[c.AUMHashes["C"]] = retainStateActive
	verdict[c.AUMHashes["E"]] = retainStateActive

	if err := markDescendantAUMs(c.Chonk(), verdict); err != nil {
		t.Errorf("markDescendantAUMs() failed: %v", err)
	}

	// Make sure the descendants got marked.
	hs := c.AUMHashes
	for _, h := range []AUMHash{hs["C2"], hs["F"], hs["G"], hs["H"], hs["E2"]} {
		if (verdict[h] & retainStateLeaf) == 0 {
			t.Errorf("%v was not marked as a descendant", h)
		}
	}
	for _, h := range []AUMHash{hs["genesis"], hs["B"], hs["D"]} {
		if (verdict[h] & retainStateLeaf) != 0 {
			t.Errorf("%v was marked as a descendant and shouldnt be", h)
		}
	}
}

func TestMarkAncestorIntersectionAUMs(t *testing.T) {
	fakeState := &State{
		Keys:               []Key{{Kind: Key25519, Votes: 1}},
		DisablementSecrets: [][]byte{bytes.Repeat([]byte{1}, 32)},
	}

	tcs := []struct {
		name            string
		chain           *testChain
		verdicts        map[string]retainState
		initialAncestor string
		wantAncestor    string
		wantRetained    []string
		wantDeleted     []string
	}{
		{
			name: "genesis",
			chain: newTestchain(t, `
                A
                A.template = checkpoint`, optTemplate("checkpoint", AUM{MessageKind: AUMCheckpoint, State: fakeState})),
			initialAncestor: "A",
			wantAncestor:    "A",
			verdicts: map[string]retainState{
				"A": retainStateActive,
			},
			wantRetained: []string{"A"},
		},
		{
			name: "no adjustment",
			chain: newTestchain(t, `
                DEAD -> A -> B -> C
                A.template = checkpoint
                B.template = checkpoint`, optTemplate("checkpoint", AUM{MessageKind: AUMCheckpoint, State: fakeState})),
			initialAncestor: "A",
			wantAncestor:    "A",
			verdicts: map[string]retainState{
				"A":    retainStateActive,
				"B":    retainStateActive,
				"C":    retainStateActive,
				"DEAD": retainStateCandidate,
			},
			wantRetained: []string{"A", "B", "C"},
			wantDeleted:  []string{"DEAD"},
		},
		{
			name: "fork",
			chain: newTestchain(t, `
                A -> B -> C -> D
                          | -> FORK
                A.template = checkpoint
                C.template = checkpoint
                D.template = checkpoint
                FORK.hashSeed = 2`, optTemplate("checkpoint", AUM{MessageKind: AUMCheckpoint, State: fakeState})),
			initialAncestor: "D",
			wantAncestor:    "C",
			verdicts: map[string]retainState{
				"A":    retainStateCandidate,
				"B":    retainStateCandidate,
				"C":    retainStateCandidate,
				"D":    retainStateActive,
				"FORK": retainStateYoung,
			},
			wantRetained: []string{"C", "D", "FORK"},
			wantDeleted:  []string{"A", "B"},
		},
		{
			name: "fork finding earlier checkpoint",
			chain: newTestchain(t, `
                A -> B -> C -> D -> E -> F
                          | -> FORK
                A.template = checkpoint
                B.template = checkpoint
                E.template = checkpoint
                FORK.hashSeed = 2`, optTemplate("checkpoint", AUM{MessageKind: AUMCheckpoint, State: fakeState})),
			initialAncestor: "E",
			wantAncestor:    "B",
			verdicts: map[string]retainState{
				"A":    retainStateCandidate,
				"B":    retainStateCandidate,
				"C":    retainStateCandidate,
				"D":    retainStateCandidate,
				"E":    retainStateActive,
				"F":    retainStateActive,
				"FORK": retainStateYoung,
			},
			wantRetained: []string{"B", "C", "D", "E", "F", "FORK"},
			wantDeleted:  []string{"A"},
		},
		{
			name: "fork multi",
			chain: newTestchain(t, `
                A -> B -> C -> D -> E
                               | -> DEADFORK
                C -> FORK
                A.template = checkpoint
                C.template = checkpoint
                D.template = checkpoint
                E.template = checkpoint
                FORK.hashSeed = 2
                DEADFORK.hashSeed = 3`, optTemplate("checkpoint", AUM{MessageKind: AUMCheckpoint, State: fakeState})),
			initialAncestor: "D",
			wantAncestor:    "C",
			verdicts: map[string]retainState{
				"A":        retainStateCandidate,
				"B":        retainStateCandidate,
				"C":        retainStateCandidate,
				"D":        retainStateActive,
				"E":        retainStateActive,
				"FORK":     retainStateYoung,
				"DEADFORK": 0,
			},
			wantRetained: []string{"C", "D", "E", "FORK"},
			wantDeleted:  []string{"A", "B", "DEADFORK"},
		},
		{
			name: "fork multi 2",
			chain: newTestchain(t, `
                A -> B -> C -> D -> E -> F -> G

                F -> F1
                D -> F2
                B -> F3

                A.template = checkpoint
                B.template = checkpoint
                D.template = checkpoint
                F.template = checkpoint
                F1.hashSeed = 2
                F2.hashSeed = 3
                F3.hashSeed = 4`, optTemplate("checkpoint", AUM{MessageKind: AUMCheckpoint, State: fakeState})),
			initialAncestor: "F",
			wantAncestor:    "B",
			verdicts: map[string]retainState{
				"A":  retainStateCandidate,
				"B":  retainStateCandidate,
				"C":  retainStateCandidate,
				"D":  retainStateCandidate,
				"E":  retainStateCandidate,
				"F":  retainStateActive,
				"G":  retainStateActive,
				"F1": retainStateYoung,
				"F2": retainStateYoung,
				"F3": retainStateYoung,
			},
			wantRetained: []string{"B", "C", "D", "E", "F", "G", "F1", "F2", "F3"},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			verdict := make(map[AUMHash]retainState, len(tc.verdicts))
			for name, v := range tc.verdicts {
				verdict[tc.chain.AUMHashes[name]] = v
			}

			got, err := markAncestorIntersectionAUMs(tc.chain.Chonk(), verdict, tc.chain.AUMHashes[tc.initialAncestor])
			if err != nil {
				t.Logf("state = %+v", verdict)
				t.Fatalf("markAncestorIntersectionAUMs() failed: %v", err)
			}
			if want := tc.chain.AUMHashes[tc.wantAncestor]; got != want {
				t.Logf("state = %+v", verdict)
				t.Errorf("lastActiveAncestor = %v, want %v", got, want)
			}

			for _, name := range tc.wantRetained {
				h := tc.chain.AUMHashes[name]
				if v := verdict[h]; v&retainAUMMask == 0 {
					t.Errorf("AUM %q was not retained: verdict = %v", name, v)
				}
			}
			for _, name := range tc.wantDeleted {
				h := tc.chain.AUMHashes[name]
				if v := verdict[h]; v&retainAUMMask != 0 {
					t.Errorf("AUM %q was retained: verdict = %v", name, v)
				}
			}

			if t.Failed() {
				for name, hash := range tc.chain.AUMHashes {
					t.Logf("AUM[%q] = %v", name, hash)
				}
			}
		})
	}
}

type compactingChonkFake struct {
	Mem

	aumAge     map[AUMHash]time.Time
	t          *testing.T
	wantDelete []AUMHash
}

func (c *compactingChonkFake) AllAUMs() ([]AUMHash, error) {
	out := make([]AUMHash, 0, len(c.Mem.aums))
	for h := range c.Mem.aums {
		out = append(out, h)
	}
	return out, nil
}

func (c *compactingChonkFake) CommitTime(hash AUMHash) (time.Time, error) {
	return c.aumAge[hash], nil
}

func hashesLess(x, y AUMHash) bool {
	return bytes.Compare(x[:], y[:]) < 0
}

func (c *compactingChonkFake) PurgeAUMs(hashes []AUMHash) error {
	if diff := cmp.Diff(c.wantDelete, hashes, cmpopts.SortSlices(hashesLess)); diff != "" {
		c.t.Errorf("deletion set differs (-want, +got):\n%s", diff)
	}
	return nil
}

// Avoid go vet complaining about copying a lock value
func cloneMem(src, dst *Mem) {
	dst.l = sync.RWMutex{}
	dst.aums = src.aums
	dst.parentIndex = src.parentIndex
	dst.lastActiveAncestor = src.lastActiveAncestor
}

func TestCompact(t *testing.T) {
	fakeState := &State{
		Keys:               []Key{{Kind: Key25519, Votes: 1}},
		DisablementSecrets: [][]byte{bytes.Repeat([]byte{1}, 32)},
	}

	// A & B are deleted because the new lastActiveAncestor advances beyond them.
	// OLD is deleted because it does not match retention criteria, and
	// though it is a descendant of the new lastActiveAncestor (C), it is not a
	// descendant of a retained AUM.
	// G, & H are retained as recent (MinChain=2) ancestors of HEAD.
	// E & F are retained because they are between retained AUMs (G+) and
	// their newest checkpoint ancestor.
	// D is retained because it is the newest checkpoint ancestor from
	// MinChain-retained AUMs.
	// G2 is retained because it is a descendant of a retained AUM (G).
	// F1 is retained because it is new enough by wall-clock time.
	// F2 is retained because it is a descendant of a retained AUM (F1).
	// C2 is retained because it is between an ancestor checkpoint and
	// a retained AUM (F1).
	// C is retained because it is the new lastActiveAncestor. It is the
	// new lastActiveAncestor because it is the newest common checkpoint
	// of all retained AUMs.
	c := newTestchain(t, `
        A -> B -> C -> C2 -> D -> E -> F -> G -> H
                       |  -> F1 -> F2       | -> G2
                       |  -> OLD

        // make {A,B,C,D} compaction candidates
        A.template = checkpoint
        B.template = checkpoint
        C.template = checkpoint
        D.template = checkpoint

        // tweak seeds of forks so hashes arent identical
        F1.hashSeed = 1
        OLD.hashSeed = 2
        G2.hashSeed = 3
    `, optTemplate("checkpoint", AUM{MessageKind: AUMCheckpoint, State: fakeState}))

	storage := &compactingChonkFake{
		aumAge:     map[AUMHash]time.Time{(c.AUMHashes["F1"]): time.Now()},
		t:          t,
		wantDelete: []AUMHash{c.AUMHashes["A"], c.AUMHashes["B"], c.AUMHashes["OLD"]},
	}

	cloneMem(c.Chonk().(*Mem), &storage.Mem)

	lastActiveAncestor, err := Compact(storage, c.AUMHashes["H"], CompactionOptions{MinChain: 2, MinAge: time.Hour})
	if err != nil {
		t.Errorf("Compact() failed: %v", err)
	}
	if lastActiveAncestor != c.AUMHashes["C"] {
		t.Errorf("last active ancestor = %v, want %v", lastActiveAncestor, c.AUMHashes["C"])
	}

	if t.Failed() {
		for name, hash := range c.AUMHashes {
			t.Logf("AUM[%q] = %v", name, hash)
		}
	}
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
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
		{Oldest: c.AUMs["G2"], Head: c.AUMs["L4"]},
		{Oldest: c.AUMs["G1"], Head: c.AUMs["L3"], chainsThroughActive: true},
		{Oldest: c.AUMs["G1"], Head: c.AUMs["L1"], chainsThroughActive: true},
		{Oldest: c.AUMs["G1"], Head: c.AUMs["L2"], chainsThroughActive: true},
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
        L1.hashSeed = 11
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
		optTemplate("removeKey", AUM{MessageKind: AUMRemoveKey, KeyID: key.MustID()}))

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
	if _, err := state.GetKey(key.MustID()); err != ErrNoSuchKey {
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
		if _, err := state.GetKey(key.MustID()); err != nil {
			t.Errorf("expected key to be present at state: err = %v", err)
		}
	}
}

// fakeAUM generates an AUM structure based on the template.
// If parent is provided, PrevAUMHash is set to that value.
//
// If template is an AUM, the returned AUM is based on that.
// If template is an int, a NOOP AUM is returned, and the
// provided int can be used to tweak the resulting hash (needed
// for tests you want one AUM to be 'lower' than another, so that
// that chain is taken based on fork resolution rules).
func fakeAUM(t *testing.T, template any, parent *AUMHash) (AUM, AUMHash) {
	if seed, ok := template.(int); ok {
		a := AUM{MessageKind: AUMNoOp, KeyID: []byte{byte(seed)}}
		if parent != nil {
			a.PrevAUMHash = (*parent)[:]
		}
		h := a.Hash()
		return a, h
	}

	if a, ok := template.(AUM); ok {
		if parent != nil {
			a.PrevAUMHash = (*parent)[:]
		}
		h := a.Hash()
		return a, h
	}

	panic("template must be an int or an AUM")
}

func TestOpenAuthority(t *testing.T) {
	pub, _ := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	//        /- L1
	// G1 - I1 - I2 - I3 -L2
	//                  \-L3
	// G2 - L4
	//
	// We set the previous-known ancestor to G1, so the
	// ancestor to start from should be G1.
	g1, g1H := fakeAUM(t, AUM{MessageKind: AUMAddKey, Key: &key}, nil)
	i1, i1H := fakeAUM(t, 2, &g1H) // AUM{MessageKind: AUMAddKey, Key: &key2}
	l1, l1H := fakeAUM(t, 13, &i1H)

	i2, i2H := fakeAUM(t, 2, &i1H)
	i3, i3H := fakeAUM(t, 5, &i2H)
	l2, l2H := fakeAUM(t, AUM{MessageKind: AUMNoOp, KeyID: []byte{7}, Signatures: []tkatype.Signature{{KeyID: key.MustID()}}}, &i3H)
	l3, l3H := fakeAUM(t, 4, &i3H)

	g2, g2H := fakeAUM(t, 8, nil)
	l4, _ := fakeAUM(t, 9, &g2H)

	// We make sure that I2 has a lower hash than L1, so
	// it should take that path rather than L1.
	if bytes.Compare(l1H[:], i2H[:]) < 0 {
		t.Fatal("failed assert: h(i2) > h(l1)\nTweak parameters to fakeAUM till this passes")
	}
	// We make sure L2 has a signature with key, so it should
	// take that path over L3. We assert that the L3 hash
	// is less than L2 so the test will fail if the signature
	// preference logic is broken.
	if bytes.Compare(l2H[:], l3H[:]) < 0 {
		t.Fatal("failed assert: h(l3) > h(l2)\nTweak parameters to fakeAUM till this passes")
	}

	// Construct the state of durable storage.
	chonk := ChonkMem()
	err := chonk.CommitVerifiedAUMs([]AUM{g1, i1, l1, i2, i3, l2, l3, g2, l4})
	if err != nil {
		t.Fatal(err)
	}
	chonk.SetLastActiveAncestor(i1H)

	a, err := Open(chonk)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	// Should include the key added in G1
	if _, err := a.state.GetKey(key.MustID()); err != nil {
		t.Errorf("missing G1 key: %v", err)
	}
	// The head of the chain should be L2.
	if a.Head() != l2H {
		t.Errorf("head was %x, want %x", a.state.LastAUMHash, l2H)
	}
}

func TestOpenAuthority_EmptyErrors(t *testing.T) {
	_, err := Open(ChonkMem())
	if err == nil {
		t.Error("Expected an error initializing an empty authority, got nil")
	}
}

func TestAuthorityHead(t *testing.T) {
	c := newTestchain(t, `
        G1 -> L1
         | -> L2

        L1.hashSeed = 2
    `)

	a, _ := Open(c.Chonk())
	if got, want := a.head.Hash(), a.Head(); got != want {
		t.Errorf("Hash() returned %x, want %x", got, want)
	}
}

func TestAuthorityValidDisablement(t *testing.T) {
	pub, _ := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}
	c := newTestchain(t, `
        G1 -> L1

        G1.template = genesis
    `,
		optTemplate("genesis", AUM{MessageKind: AUMCheckpoint, State: &State{
			Keys:               []Key{key},
			DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
		}}),
	)

	a, _ := Open(c.Chonk())
	if valid := a.ValidDisablement([]byte{1, 2, 3}); !valid {
		t.Error("ValidDisablement() returned false, want true")
	}
}

func TestCreateBootstrapAuthority(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	a1, genesisAUM, err := Create(ChonkMem(), State{
		Keys:               []Key{key},
		DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
	}, signer25519(priv))
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	a2, err := Bootstrap(ChonkMem(), genesisAUM)
	if err != nil {
		t.Fatalf("Bootstrap() failed: %v", err)
	}

	if a1.Head() != a2.Head() {
		t.Fatal("created and bootstrapped authority differ")
	}

	// Both authorities should trust the key laid down in the genesis state.
	if !a1.KeyTrusted(key.MustID()) {
		t.Error("a1 did not trust genesis key")
	}
	if !a2.KeyTrusted(key.MustID()) {
		t.Error("a2 did not trust genesis key")
	}
}

func TestAuthorityInformNonLinear(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	c := newTestchain(t, `
        G1 -> L1
         | -> L2 -> L3
               | -> L4 -> L5

        G1.template = genesis
        L1.hashSeed = 3
        L2.hashSeed = 2
        L4.hashSeed = 2
    `,
		optTemplate("genesis", AUM{MessageKind: AUMCheckpoint, State: &State{
			Keys:               []Key{key},
			DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
		}}),
		optKey("key", key, priv),
		optSignAllUsing("key"))

	storage := ChonkMem()
	a, err := Bootstrap(storage, c.AUMs["G1"])
	if err != nil {
		t.Fatalf("Bootstrap() failed: %v", err)
	}

	// L2 does not chain from L1, disabling the isHeadChain optimization
	// and forcing Inform() to take the slow path.
	informAUMs := []AUM{c.AUMs["L1"], c.AUMs["L2"], c.AUMs["L3"], c.AUMs["L4"], c.AUMs["L5"]}

	if err := a.Inform(storage, informAUMs); err != nil {
		t.Fatalf("Inform() failed: %v", err)
	}
	for i, update := range informAUMs {
		stored, err := storage.AUM(update.Hash())
		if err != nil {
			t.Errorf("reading stored update %d: %v", i, err)
			continue
		}
		if diff := cmp.Diff(update, stored); diff != "" {
			t.Errorf("update %d differs (-want, +got):\n%s", i, diff)
		}
	}

	if a.Head() != c.AUMHashes["L3"] {
		t.Fatal("authority did not converge to correct AUM")
	}
}

func TestAuthorityInformLinear(t *testing.T) {
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

	storage := ChonkMem()
	a, err := Bootstrap(storage, c.AUMs["G1"])
	if err != nil {
		t.Fatalf("Bootstrap() failed: %v", err)
	}

	informAUMs := []AUM{c.AUMs["L1"], c.AUMs["L2"], c.AUMs["L3"]}

	if err := a.Inform(storage, informAUMs); err != nil {
		t.Fatalf("Inform() failed: %v", err)
	}
	for i, update := range informAUMs {
		stored, err := storage.AUM(update.Hash())
		if err != nil {
			t.Errorf("reading stored update %d: %v", i, err)
			continue
		}
		if diff := cmp.Diff(update, stored); diff != "" {
			t.Errorf("update %d differs (-want, +got):\n%s", i, diff)
		}
	}

	if a.Head() != c.AUMHashes["L3"] {
		t.Fatal("authority did not converge to correct AUM")
	}
}

func TestInteropWithNLKey(t *testing.T) {
	priv1 := key.NewNLPrivate()
	pub1 := priv1.Public()
	pub2 := key.NewNLPrivate().Public()
	pub3 := key.NewNLPrivate().Public()

	a, _, err := Create(ChonkMem(), State{
		Keys: []Key{
			{
				Kind:   Key25519,
				Votes:  1,
				Public: pub1.KeyID(),
			},
			{
				Kind:   Key25519,
				Votes:  1,
				Public: pub2.KeyID(),
			},
		},
		DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
	}, priv1)
	if err != nil {
		t.Errorf("tka.Create: %v", err)
		return
	}

	if !a.KeyTrusted(pub1.KeyID()) {
		t.Error("pub1 want trusted, got untrusted")
	}
	if !a.KeyTrusted(pub2.KeyID()) {
		t.Error("pub2 want trusted, got untrusted")
	}
	if a.KeyTrusted(pub3.KeyID()) {
		t.Error("pub3 want untrusted, got trusted")
	}
}

func TestAuthorityCompact(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	c := newTestchain(t, `
        G -> A -> B -> C -> D -> E

        G.template = genesis
        C.template = checkpoint2
    `,
		optTemplate("genesis", AUM{MessageKind: AUMCheckpoint, State: &State{
			Keys:               []Key{key},
			DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
		}}),
		optTemplate("checkpoint2", AUM{MessageKind: AUMCheckpoint, State: &State{
			Keys:               []Key{key},
			DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
		}}),
		optKey("key", key, priv),
		optSignAllUsing("key"))

	storage := &FS{base: t.TempDir()}
	a, err := Bootstrap(storage, c.AUMs["G"])
	if err != nil {
		t.Fatalf("Bootstrap() failed: %v", err)
	}
	a.Inform(storage, []AUM{c.AUMs["A"], c.AUMs["B"], c.AUMs["C"], c.AUMs["D"], c.AUMs["E"]})

	// Should compact down to C -> D -> E
	if err := a.Compact(storage, CompactionOptions{MinChain: 2, MinAge: 1}); err != nil {
		t.Fatal(err)
	}
	if a.oldestAncestor.Hash() != c.AUMHashes["C"] {
		t.Errorf("ancestor = %v, want %v", a.oldestAncestor.Hash(), c.AUMHashes["C"])
	}

	// Make sure the stored authority is still openable and resolves to the same state.
	stored, err := Open(storage)
	if err != nil {
		t.Fatalf("Failed to open stored authority: %v", err)
	}
	if stored.Head() != a.Head() {
		t.Errorf("Stored authority head differs: head = %v, want %v", stored.Head(), a.Head())
	}
	t.Logf("original ancestor = %v", c.AUMHashes["G"])
	if anc, _ := storage.LastActiveAncestor(); *anc != c.AUMHashes["C"] {
		t.Errorf("ancestor = %v, want %v", anc, c.AUMHashes["C"])
	}
}

func TestFindParentForRewrite(t *testing.T) {
	pub, _ := testingKey25519(t, 1)
	k1 := Key{Kind: Key25519, Public: pub, Votes: 1}

	pub2, _ := testingKey25519(t, 2)
	k2 := Key{Kind: Key25519, Public: pub2, Votes: 1}
	k2ID, _ := k2.ID()
	pub3, _ := testingKey25519(t, 3)
	k3 := Key{Kind: Key25519, Public: pub3, Votes: 1}

	c := newTestchain(t, `
        A -> B -> C -> D -> E
        A.template = genesis
        B.template = add2
        C.template = add3
        D.template = remove2
    `,
		optTemplate("genesis", AUM{MessageKind: AUMCheckpoint, State: &State{
			Keys:               []Key{k1},
			DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
		}}),
		optTemplate("add2", AUM{MessageKind: AUMAddKey, Key: &k2}),
		optTemplate("add3", AUM{MessageKind: AUMAddKey, Key: &k3}),
		optTemplate("remove2", AUM{MessageKind: AUMRemoveKey, KeyID: k2ID}))

	a, err := Open(c.Chonk())
	if err != nil {
		t.Fatal(err)
	}

	// k1 was trusted at genesis, so there's no better rewrite parent
	// than the genesis.
	k1ID, _ := k1.ID()
	k1P, err := a.findParentForRewrite(c.Chonk(), []tkatype.KeyID{k1ID}, k1ID)
	if err != nil {
		t.Fatalf("FindParentForRewrite(k1) failed: %v", err)
	}
	if k1P != a.oldestAncestor.Hash() {
		t.Errorf("FindParentForRewrite(k1) = %v, want %v", k1P, a.oldestAncestor.Hash())
	}

	// k3 was trusted at C, so B would be an ideal rewrite point.
	k3ID, _ := k3.ID()
	k3P, err := a.findParentForRewrite(c.Chonk(), []tkatype.KeyID{k3ID}, k1ID)
	if err != nil {
		t.Fatalf("FindParentForRewrite(k3) failed: %v", err)
	}
	if k3P != c.AUMHashes["B"] {
		t.Errorf("FindParentForRewrite(k3) = %v, want %v", k3P, c.AUMHashes["B"])
	}

	// k2 was added but then removed, so HEAD is an appropriate rewrite point.
	k2P, err := a.findParentForRewrite(c.Chonk(), []tkatype.KeyID{k2ID}, k1ID)
	if err != nil {
		t.Fatalf("FindParentForRewrite(k2) failed: %v", err)
	}
	if k3P != c.AUMHashes["B"] {
		t.Errorf("FindParentForRewrite(k2) = %v, want %v", k2P, a.Head())
	}

	// There's no appropriate point where both k2 and k3 are simultaneously not trusted,
	// so the best rewrite point is the genesis AUM.
	doubleP, err := a.findParentForRewrite(c.Chonk(), []tkatype.KeyID{k2ID, k3ID}, k1ID)
	if err != nil {
		t.Fatalf("FindParentForRewrite({k2, k3}) failed: %v", err)
	}
	if doubleP != a.oldestAncestor.Hash() {
		t.Errorf("FindParentForRewrite({k2, k3}) = %v, want %v", doubleP, a.oldestAncestor.Hash())
	}
}

func TestMakeRetroactiveRevocation(t *testing.T) {
	pub, _ := testingKey25519(t, 1)
	k1 := Key{Kind: Key25519, Public: pub, Votes: 1}

	pub2, _ := testingKey25519(t, 2)
	k2 := Key{Kind: Key25519, Public: pub2, Votes: 1}
	pub3, _ := testingKey25519(t, 3)
	k3 := Key{Kind: Key25519, Public: pub3, Votes: 1}

	c := newTestchain(t, `
        A -> B -> C -> D
        A.template = genesis
        C.template = add2
        D.template = add3
    `,
		optTemplate("genesis", AUM{MessageKind: AUMCheckpoint, State: &State{
			Keys:               []Key{k1},
			DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
		}}),
		optTemplate("add2", AUM{MessageKind: AUMAddKey, Key: &k2}),
		optTemplate("add3", AUM{MessageKind: AUMAddKey, Key: &k3}))

	a, err := Open(c.Chonk())
	if err != nil {
		t.Fatal(err)
	}

	// k2 was added by C, so a forking revocation should:
	// - have B as a parent
	// - trust the remaining keys at the time, k1 & k3.
	k1ID, _ := k1.ID()
	k2ID, _ := k2.ID()
	k3ID, _ := k3.ID()
	forkingAUM, err := a.MakeRetroactiveRevocation(c.Chonk(), []tkatype.KeyID{k2ID}, k1ID, AUMHash{})
	if err != nil {
		t.Fatalf("MakeRetroactiveRevocation(k2) failed: %v", err)
	}
	if bHash := c.AUMHashes["B"]; !bytes.Equal(forkingAUM.PrevAUMHash, bHash[:]) {
		t.Errorf("forking AUM has parent %v, want %v", forkingAUM.PrevAUMHash, bHash[:])
	}
	if _, err := forkingAUM.State.GetKey(k1ID); err != nil {
		t.Error("Forked state did not trust k1")
	}
	if _, err := forkingAUM.State.GetKey(k3ID); err != nil {
		t.Error("Forked state did not trust k3")
	}
	if _, err := forkingAUM.State.GetKey(k2ID); err == nil {
		t.Error("Forked state trusted removed-key k2")
	}

	// Test that removing all trusted keys results in an error.
	_, err = a.MakeRetroactiveRevocation(c.Chonk(), []tkatype.KeyID{k1ID, k2ID, k3ID}, k1ID, AUMHash{})
	if wantErr := "cannot revoke all trusted keys"; err == nil || err.Error() != wantErr {
		t.Fatalf("MakeRetroactiveRevocation({k1, k2, k3}) returned %v, expected %q", err, wantErr)
	}
}

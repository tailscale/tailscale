// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"crypto/ed25519"
	"sort"
	"testing"
)

type scenarioNode struct {
	Name string
	A    *Authority
	AUMs map[string]AUM

	storage Chonk
}

type scenarioTest struct {
	t *testing.T

	defaultKey  *Key
	defaultPriv ed25519.PrivateKey

	initial *testChain

	nodes map[string]*scenarioNode
}

func (s *scenarioTest) mkNode(name string) *scenarioNode {
	storage := s.initial.Chonk()
	authority, err := Open(storage)
	if err != nil {
		s.t.Fatal(err)
	}

	aums := make(map[string]AUM, len(s.initial.AUMs))
	for k, v := range s.initial.AUMs {
		aums[k] = v
	}

	n := &scenarioNode{
		A:       authority,
		AUMs:    aums,
		Name:    name,
		storage: storage,
	}

	s.nodes[name] = n
	return n
}

// mkNodeWithForks creates a new node based on the initial AUMs in the
// scenario, but additionally with the forking chains applied.
//
// chains is expected to be a map containing chains that should be known
// by this node, with the key being the parent AUM the chain extends from.
func (s *scenarioTest) mkNodeWithForks(name string, signWithDefault bool, chains map[string]*testChain) *scenarioNode {
	n := s.mkNode(name)

	// re-jig the provided chain to be based on the provided parent,
	// and optionally signed with the default key.
	for parentName, chain := range chains {
		parent, exists := n.AUMs[parentName]
		if !exists {
			panic("cannot use nonexistent parent: " + parentName)
		}
		parentHash := parent.Hash()
		chain.Nodes[chain.FirstIdent].ParentHash = &parentHash

		if signWithDefault {
			chain.Key["default_key"] = s.defaultKey
			chain.KeyPrivs["default_key"] = s.defaultPriv
			chain.SignAllKeys = append(chain.SignAllKeys, "default_key")
		}
		chain.buildChain()

		aums := make([]AUM, 0, len(chain.AUMs))
		for name, a := range chain.AUMs {
			aums = append(aums, a)
			n.AUMs[name] = a
		}
		// AUMs passed to Inform need to be ordered in
		// from ancestor to leaf.
		sort.SliceStable(aums, func(i, j int) bool {
			jParent, _ := aums[j].Parent()
			if aums[i].Hash() == jParent {
				return true
			}
			return false
		})
		if err := n.A.Inform(n.storage, aums); err != nil {
			panic(err)
		}
	}

	return n
}

func (s *scenarioTest) syncBetween(n1, n2 *scenarioNode) error {
	o1, err := n1.A.SyncOffer(n1.storage)
	if err != nil {
		return err
	}
	o2, err := n2.A.SyncOffer(n2.storage)
	if err != nil {
		return err
	}

	aumsFrom1, err := n1.A.MissingAUMs(n1.storage, o2)
	if err != nil {
		return err
	}
	aumsFrom2, err := n2.A.MissingAUMs(n2.storage, o1)
	if err != nil {
		return err
	}
	if err := n2.A.Inform(n2.storage, aumsFrom1); err != nil {
		return err
	}
	if err := n1.A.Inform(n1.storage, aumsFrom2); err != nil {
		return err
	}
	return nil
}

func (s *scenarioTest) testSyncsBetween(n1, n2 *scenarioNode) {
	if err := s.syncBetween(n1, n2); err != nil {
		s.t.Fatal(err)
	}
}

func (s *scenarioTest) checkHaveConsensus(n1, n2 *scenarioNode) {
	if h1, h2 := n1.A.Head(), n2.A.Head(); h1 != h2 {
		s.t.Errorf("node %s & %s are not in sync", n1.Name, n2.Name)
	}
}

// testScenario implements scaffolding for testing that authorities
// with different head states can synchronize.
//
// sharedChain and sharedOptions are passed to testChain to create an
// initial set of AUMs which all nodes know about. A default key and genesis
// AUM are created for you under the template 'genesis' and key 'key'.
func testScenario(t *testing.T, sharedChain string, sharedOptions ...testchainOpt) *scenarioTest {
	t.Helper()
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 1}
	sharedOptions = append(sharedOptions,
		optTemplate("genesis", AUM{MessageKind: AUMCheckpoint, State: &State{
			Keys:               []Key{key},
			DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
		}}),
		optKey("key", key, priv),
		optSignAllUsing("key"))

	return &scenarioTest{
		t:           t,
		defaultKey:  &key,
		defaultPriv: priv,
		initial:     newTestchain(t, sharedChain, sharedOptions...),
		nodes:       map[string]*scenarioNode{},
	}
}

func TestScenarioHelpers(t *testing.T) {
	s := testScenario(t, `
        G -> L1
        G.template = genesis
    `)
	control := s.mkNode("control")

	n := s.mkNodeWithForks("n", true, map[string]*testChain{
		"L1": newTestchain(t, `L2 -> L3`),
	})

	// Make sure node has both the initial AUMs and the
	// chain from L1.
	if _, ok := n.AUMs["G"]; !ok {
		t.Errorf("node n is missing %s", "G")
	}
	if _, ok := n.AUMs["L1"]; !ok {
		t.Errorf("node n is missing %s", "L1")
	}
	if _, ok := n.AUMs["L2"]; !ok {
		t.Errorf("node n is missing %s", "L2")
	}
	if _, ok := n.AUMs["L3"]; !ok {
		t.Errorf("node n is missing %s", "L3")
	}
	if err := signatureVerify(&n.AUMs["L3"].Signatures[0], n.AUMs["L3"].SigHash(), *s.defaultKey); err != nil {
		t.Errorf("chained AUM was not signed: %v", err)
	}

	s.testSyncsBetween(control, n)
	s.checkHaveConsensus(control, n)
}

func TestNormalPropagation(t *testing.T) {
	s := testScenario(t, `
        G -> L1 -> L2
        G.template = genesis
    `)
	control := s.mkNode("control")

	// Let's say there's a node with some updates!
	n1 := s.mkNodeWithForks("n1", true, map[string]*testChain{
		"L2": newTestchain(t, `L3 -> L4`),
	})
	// Can control haz the updates?
	s.testSyncsBetween(control, n1)
	s.checkHaveConsensus(control, n1)

	// A new node came online, can the new node learn everything
	// just via control?
	n2 := s.mkNode("n2")
	s.testSyncsBetween(control, n2)
	s.checkHaveConsensus(control, n2)

	// So by virtue of syncing with control n2 should be at the same
	// state as n1.
	s.checkHaveConsensus(n1, n2)
}

func TestForkingPropagation(t *testing.T) {
	pub, priv := testingKey25519(t, 2)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	addKey2 := AUM{MessageKind: AUMAddKey, Key: &key}

	s := testScenario(t, `
        G -> AddSecondKey -> L1 -> L2
        G.template = genesis
        AddSecondKey.template = addKey2
        `,
		optKey("key2", key, priv),
		optTemplate("addKey2", addKey2))

	control := s.mkNode("control")

	// Random, non-forking updates from n1
	n1 := s.mkNodeWithForks("n1", true, map[string]*testChain{
		"L2": newTestchain(t, `L3 -> L4`),
	})
	// Can control haz the updates?
	s.testSyncsBetween(control, n1)
	s.checkHaveConsensus(control, n1)

	// Ooooo what about a forking update?
	n2 := s.mkNodeWithForks("n2", false, map[string]*testChain{
		"L1": newTestchain(t,
			`F1 -> F2
             F1.template = removeKey1`,
			optSignAllUsing("key2"),
			optKey("key2", key, priv),
			optTemplate("removeKey1", AUM{MessageKind: AUMRemoveKey, KeyID: s.defaultKey.MustID()})),
	})
	s.testSyncsBetween(control, n2)
	s.checkHaveConsensus(control, n2)

	// No wozzles propagating from n2->CTRL, what about CTRL->n1?
	s.testSyncsBetween(control, n1)
	s.checkHaveConsensus(n1, n2)

	if _, err := n1.A.state.GetKey(s.defaultKey.MustID()); err != ErrNoSuchKey {
		t.Error("default key was still present")
	}
	if _, err := n1.A.state.GetKey(key.MustID()); err != nil {
		t.Errorf("key2 was not trusted: %v", err)
	}
}

func TestInvalidAUMPropagationRejected(t *testing.T) {
	s := testScenario(t, `
        G -> L1 -> L2
        G.template = genesis
    `)
	control := s.mkNode("control")

	// Construct an invalid L4 AUM, and manually apply it to n1,
	// resulting in a corrupted Authority.
	n1 := s.mkNodeWithForks("n1", true, map[string]*testChain{
		"L2": newTestchain(t, `L3`),
	})
	l3 := n1.AUMs["L3"]
	l3H := l3.Hash()
	l4 := AUM{MessageKind: AUMAddKey, PrevAUMHash: l3H[:]}
	if err := l4.sign25519(s.defaultPriv); err != nil {
		t.Fatal(err)
	}
	l4H := l4.Hash()
	n1.storage.CommitVerifiedAUMs([]AUM{l4})
	n1.A.state.LastAUMHash = &l4H

	// Does control nope out with syncing?
	if err := s.syncBetween(control, n1); err == nil {
		t.Error("sync with invalid AUM was successful")
	}

	// Control should not have accepted ANY of the updates, even
	// though L3 was well-formed.
	l2 := control.AUMs["L2"]
	l2H := l2.Hash()
	if control.A.Head() != l2H {
		t.Errorf("head was %x, expected %x", control.A.Head(), l2H)
	}
}

func TestUnsignedAUMPropagationRejected(t *testing.T) {
	s := testScenario(t, `
        G -> L1 -> L2
        G.template = genesis
    `)
	control := s.mkNode("control")

	// Construct an unsigned L4 AUM, and manually apply it to n1,
	// resulting in a corrupted Authority.
	n1 := s.mkNodeWithForks("n1", true, map[string]*testChain{
		"L2": newTestchain(t, `L3`),
	})
	l3 := n1.AUMs["L3"]
	l3H := l3.Hash()
	l4 := AUM{MessageKind: AUMNoOp, PrevAUMHash: l3H[:]}
	l4H := l4.Hash()
	n1.storage.CommitVerifiedAUMs([]AUM{l4})
	n1.A.state.LastAUMHash = &l4H

	// Does control nope out with syncing?
	if err := s.syncBetween(control, n1); err == nil || err.Error() != "update 1 invalid: unsigned AUM" {
		t.Errorf("sync with unsigned AUM was successful (err = %v)", err)
	}

	// Control should not have accepted ANY of the updates, even
	// though L3 was well-formed.
	l2 := control.AUMs["L2"]
	l2H := l2.Hash()
	if control.A.Head() != l2H {
		t.Errorf("head was %x, expected %x", control.A.Head(), l2H)
	}
}

func TestBadSigAUMPropagationRejected(t *testing.T) {
	s := testScenario(t, `
        G -> L1 -> L2
        G.template = genesis
    `)
	control := s.mkNode("control")

	// Construct a otherwise-valid L4 AUM but mess up the signature.
	n1 := s.mkNodeWithForks("n1", true, map[string]*testChain{
		"L2": newTestchain(t, `L3`),
	})
	l3 := n1.AUMs["L3"]
	l3H := l3.Hash()
	l4 := AUM{MessageKind: AUMNoOp, PrevAUMHash: l3H[:]}
	if err := l4.sign25519(s.defaultPriv); err != nil {
		t.Fatal(err)
	}
	l4.Signatures[0].Signature[3] = 42
	l4H := l4.Hash()
	n1.storage.CommitVerifiedAUMs([]AUM{l4})
	n1.A.state.LastAUMHash = &l4H

	// Does control nope out with syncing?
	if err := s.syncBetween(control, n1); err == nil || err.Error() != "update 1 invalid: signature 0: invalid signature" {
		t.Errorf("sync with unsigned AUM was successful (err = %v)", err)
	}

	// Control should not have accepted ANY of the updates, even
	// though L3 was well-formed.
	l2 := control.AUMs["L2"]
	l2H := l2.Hash()
	if control.A.Head() != l2H {
		t.Errorf("head was %x, expected %x", control.A.Head(), l2H)
	}
}

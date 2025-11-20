// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"text/scanner"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/types/tkatype"
)

// chaintest_test.go implements test helpers for concisely describing
// chains of possibly signed AUMs, to assist in making tests shorter and
// easier to read.

// parsed representation of a named AUM in a test chain.
type testchainNode struct {
	Name   string
	Parent string
	Uses   []scanner.Position

	HashSeed   int
	Template   string
	SignedWith string

	// When set, uses this hash as the parent hash when
	// Parent is not set.
	//
	// Set when a testChain is based on a different one
	// (in scenario_test.go).
	ParentHash *AUMHash
}

// testChain represents a constructed web of AUMs for testing purposes.
type testChain struct {
	FirstIdent string
	Nodes      map[string]*testchainNode
	AUMs       map[string]AUM
	AUMHashes  map[string]AUMHash

	// Configured by options to NewTestchain()
	Template    map[string]AUM
	Key         map[string]*Key
	KeyPrivs    map[string]ed25519.PrivateKey
	SignAllKeys []string
}

// newTestchain constructs a web of AUMs based on the provided input and
// options.
//
// Input is expected to be a graph & tweaks, looking like this:
//
//	G1 -> A -> B
//	      | -> C
//
// which defines AUMs G1, A, B, and C; with G1 having no parent, A having
// G1 as a parent, and both B & C having A as a parent.
//
// Tweaks are specified like this:
//
//	<AUM>.<tweak> = <value>
//
// for example: G1.hashSeed = 2
//
// There are 3 available tweaks:
//   - hashSeed: Set to an integer to tweak the AUM hash of that AUM.
//   - template: Set to the name of a template provided via optTemplate().
//     The template is copied and use as the content for that AUM.
//   - signedWith: Set to the name of a key provided via optKey(). This
//     key is used to sign that AUM.
func newTestchain(t *testing.T, input string, options ...testchainOpt) *testChain {
	t.Helper()

	var (
		s   scanner.Scanner
		out = testChain{
			Nodes:    map[string]*testchainNode{},
			Template: map[string]AUM{},
			Key:      map[string]*Key{},
			KeyPrivs: map[string]ed25519.PrivateKey{},
		}
	)

	// Process any options
	for _, o := range options {
		if o.Template != nil {
			out.Template[o.Name] = *o.Template
		}
		if o.Key != nil {
			out.Key[o.Name] = o.Key
			out.KeyPrivs[o.Name] = o.Private
		}
		if o.SignAllWith {
			out.SignAllKeys = append(out.SignAllKeys, o.Name)
		}
	}

	s.Init(strings.NewReader(input))
	s.Mode = scanner.ScanIdents | scanner.SkipComments | scanner.ScanComments | scanner.ScanChars | scanner.ScanInts
	s.Whitespace ^= 1 << '\t' // clear tabs
	var (
		lastIdent    string
		lastWasChain bool // if the last token was '->'
	)
	for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
		switch tok {
		case '\t':
			t.Fatalf("tabs disallowed, use spaces (seen at %v)", s.Pos())

		case '.': // tweaks, like <ident>.hashSeed = <val>
			s.Scan()
			tweak := s.TokenText()
			if tok := s.Scan(); tok == '=' {
				s.Scan()
				switch tweak {
				case "hashSeed":
					out.Nodes[lastIdent].HashSeed, _ = strconv.Atoi(s.TokenText())
				case "template":
					out.Nodes[lastIdent].Template = s.TokenText()
				case "signedWith":
					out.Nodes[lastIdent].SignedWith = s.TokenText()
				}
			}

		case scanner.Ident:
			out.recordPos(s.TokenText(), s.Pos())
			// If the last token was '->', that means
			// that the next identifier has a child relationship
			// with the identifier preceding '->'.
			if lastWasChain {
				out.recordParent(t, s.TokenText(), lastIdent)
			}
			lastIdent = s.TokenText()
			if out.FirstIdent == "" {
				out.FirstIdent = s.TokenText()
			}

		case '-': // handle '->'
			switch s.Peek() {
			case '>':
				s.Scan()
				lastWasChain = true
				continue
			}

		case '|': // handle '|'
			line, col := s.Pos().Line, s.Pos().Column
		nodeLoop:
			for _, n := range out.Nodes {
				for _, p := range n.Uses {
					// Find the identifier used right here on the line above.
					if p.Line == line-1 && col <= p.Column && col > p.Column-len(n.Name) {
						lastIdent = n.Name
						out.recordPos(n.Name, s.Pos())
						break nodeLoop
					}
				}
			}
		}
		lastWasChain = false
		// t.Logf("tok = %v, %q", tok, s.TokenText())
	}

	out.buildChain()
	return &out
}

// called from the parser to record the location of an
// identifier (a named AUM).
func (c *testChain) recordPos(ident string, pos scanner.Position) {
	n := c.Nodes[ident]
	if n == nil {
		n = &testchainNode{Name: ident}
	}

	n.Uses = append(n.Uses, pos)
	c.Nodes[ident] = n
}

// called from the parser to record a parent relationship between
// two AUMs.
func (c *testChain) recordParent(t *testing.T, child, parent string) {
	if p := c.Nodes[child].Parent; p != "" && p != parent {
		t.Fatalf("differing parent specified for %s: %q != %q", child, p, parent)
	}
	c.Nodes[child].Parent = parent
}

// called after parsing to build the web of AUM structures.
// This method populates c.AUMs and c.AUMHashes.
func (c *testChain) buildChain() {
	pending := make(map[string]*testchainNode, len(c.Nodes))
	for k, v := range c.Nodes {
		pending[k] = v
	}

	// AUMs with a parent need to know their hash, so we
	// only compute AUMs who's parents have been computed
	// each iteration. Since at least the genesis AUM
	// had no parent, theres always a path to completion
	// in O(n+1) where n is the number of AUMs.
	c.AUMs = make(map[string]AUM, len(c.Nodes))
	c.AUMHashes = make(map[string]AUMHash, len(c.Nodes))
	for range len(c.Nodes) + 1 {
		if len(pending) == 0 {
			return
		}

		next := make([]*testchainNode, 0, 10)
		for _, v := range pending {
			if _, parentPending := pending[v.Parent]; !parentPending {
				next = append(next, v)
			}
		}

		for _, v := range next {
			aum := c.makeAUM(v)
			h := aum.Hash()

			c.AUMHashes[v.Name] = h
			c.AUMs[v.Name] = aum
			delete(pending, v.Name)
		}
	}
	panic("unexpected: incomplete despite len(Nodes)+1 iterations")
}

func (c *testChain) makeAUM(v *testchainNode) AUM {
	// By default, the AUM used is just a no-op AUM
	// with a parent hash set (if any).
	//
	// If <AUM>.template is set to the same name as in
	// a provided optTemplate(), the AUM is built
	// from a copy of that instead.
	//
	// If <AUM>.hashSeed = <int> is set, the KeyID is
	// tweaked to effect tweaking the hash. This is useful
	// if you want one AUM to have a lower hash than another.
	aum := AUM{MessageKind: AUMNoOp}
	if template := v.Template; template != "" {
		aum = c.Template[template]
	}
	if v.Parent != "" {
		parentHash := c.AUMHashes[v.Parent]
		aum.PrevAUMHash = parentHash[:]
	} else if v.ParentHash != nil {
		aum.PrevAUMHash = (*v.ParentHash)[:]
	}
	if seed := v.HashSeed; seed != 0 {
		aum.KeyID = []byte{byte(seed)}
	}
	if err := aum.StaticValidate(); err != nil {
		// Usually caused by a test writer specifying a template
		// AUM which is ultimately invalid.
		panic(fmt.Sprintf("aum %+v failed static validation: %v", aum, err))
	}

	sigHash := aum.SigHash()
	for _, key := range c.SignAllKeys {
		aum.Signatures = append(aum.Signatures, tkatype.Signature{
			KeyID:     c.Key[key].MustID(),
			Signature: ed25519.Sign(c.KeyPrivs[key], sigHash[:]),
		})
	}

	// If the aum was specified as being signed by some key, then
	// sign it using that key.
	if key := v.SignedWith; key != "" {
		aum.Signatures = append(aum.Signatures, tkatype.Signature{
			KeyID:     c.Key[key].MustID(),
			Signature: ed25519.Sign(c.KeyPrivs[key], sigHash[:]),
		})
	}

	return aum
}

// Chonk returns a tailchonk containing all AUMs.
func (c *testChain) Chonk() Chonk {
	out := ChonkMem()
	for _, update := range c.AUMs {
		if err := out.CommitVerifiedAUMs([]AUM{update}); err != nil {
			panic(err)
		}
	}
	return out
}

// ChonkWith returns a tailchonk containing the named AUMs.
func (c *testChain) ChonkWith(names ...string) Chonk {
	out := ChonkMem()
	for _, name := range names {
		update := c.AUMs[name]
		if err := out.CommitVerifiedAUMs([]AUM{update}); err != nil {
			panic(err)
		}
	}
	return out
}

type testchainOpt struct {
	Name        string
	Template    *AUM
	Key         *Key
	Private     ed25519.PrivateKey
	SignAllWith bool
}

func optTemplate(name string, template AUM) testchainOpt {
	return testchainOpt{
		Name:     name,
		Template: &template,
	}
}

func optKey(name string, key Key, priv ed25519.PrivateKey) testchainOpt {
	return testchainOpt{
		Name:    name,
		Key:     &key,
		Private: priv,
	}
}

func optSignAllUsing(keyName string) testchainOpt {
	return testchainOpt{
		Name:        keyName,
		SignAllWith: true,
	}
}

func TestNewTestchain(t *testing.T) {
	c := newTestchain(t, `
        genesis -> B -> C
                   | -> D
                   | -> E -> F

        E.hashSeed = 12 // tweak E to have the lowest hash so its chosen
        F.template = test
    `, optTemplate("test", AUM{MessageKind: AUMNoOp, KeyID: []byte{10}}))

	want := map[string]*testchainNode{
		"genesis": {Name: "genesis", Uses: []scanner.Position{{Line: 2, Column: 16}}},
		"B": {
			Name:   "B",
			Parent: "genesis",
			Uses:   []scanner.Position{{Line: 2, Column: 21}, {Line: 3, Column: 21}, {Line: 4, Column: 21}},
		},
		"C": {Name: "C", Parent: "B", Uses: []scanner.Position{{Line: 2, Column: 26}}},
		"D": {Name: "D", Parent: "B", Uses: []scanner.Position{{Line: 3, Column: 26}}},
		"E": {Name: "E", Parent: "B", HashSeed: 12, Uses: []scanner.Position{{Line: 4, Column: 26}, {Line: 6, Column: 10}}},
		"F": {Name: "F", Parent: "E", Template: "test", Uses: []scanner.Position{{Line: 4, Column: 31}, {Line: 7, Column: 10}}},
	}

	if diff := cmp.Diff(want, c.Nodes, cmpopts.IgnoreFields(scanner.Position{}, "Offset")); diff != "" {
		t.Errorf("decoded state differs (-want, +got):\n%s", diff)
	}
	if !bytes.Equal(c.AUMs["F"].KeyID, []byte{10}) {
		t.Errorf("AUM 'F' missing KeyID from template: %v", c.AUMs["F"])
	}

	// chonk := c.Chonk()
	// authority, err := Open(chonk)
	// if err != nil {
	// 	t.Errorf("failed to initialize from chonk: %v", err)
	// }

	// if authority.Head() != c.AUMHashes["F"] {
	// 	t.Errorf("head = %X, want %X", authority.Head(), c.AUMHashes["F"])
	// }
}

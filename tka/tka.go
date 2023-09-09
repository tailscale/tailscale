// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tka (WIP) implements the Tailnet Key Authority.
package tka

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/fxamacker/cbor/v2"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
	"tailscale.com/util/set"
)

// Strict settings for the CBOR decoder.
var cborDecOpts = cbor.DecOptions{
	DupMapKey:   cbor.DupMapKeyEnforcedAPF,
	IndefLength: cbor.IndefLengthForbidden,
	TagsMd:      cbor.TagsForbidden,

	// Arbitrarily-chosen maximums.
	MaxNestedLevels:  16, // Most likely to be hit for SigRotation sigs.
	MaxArrayElements: 4096,
	MaxMapPairs:      1024,
}

// Arbitrarily chosen limit on scanning AUM trees.
const maxScanIterations = 2000

// Authority is a Tailnet Key Authority. This type is the main coupling
// point to the rest of the tailscale client.
//
// Authority objects can either be created from an existing, non-empty
// tailchonk (via tka.Open()), or created from scratch using tka.Bootstrap()
// or tka.Create().
type Authority struct {
	head           AUM
	oldestAncestor AUM
	state          State
}

// Clone duplicates the Authority structure.
func (a *Authority) Clone() *Authority {
	return &Authority{
		head:           a.head,
		oldestAncestor: a.oldestAncestor,
		state:          a.state.Clone(),
	}
}

// A chain describes a linear sequence of updates from Oldest to Head,
// resulting in some State at Head.
type chain struct {
	Oldest AUM
	Head   AUM

	state State

	// Set to true if the AUM chain intersects with the active
	// chain from a previous run.
	chainsThroughActive bool
}

// computeChainCandidates returns all possible chains based on AUMs stored
// in the given tailchonk. A chain is defined as a unique (oldest, newest)
// AUM tuple. chain.state is not yet populated in returned chains.
//
// If lastKnownOldest is provided, any chain that includes the given AUM
// has the chainsThroughActive field set to true. This bit is leveraged
// in computeActiveAncestor() to filter out irrelevant chains when determining
// the active ancestor from a list of distinct chains.
func computeChainCandidates(storage Chonk, lastKnownOldest *AUMHash, maxIter int) ([]chain, error) {
	heads, err := storage.Heads()
	if err != nil {
		return nil, fmt.Errorf("reading heads: %v", err)
	}
	candidates := make([]chain, len(heads))
	for i := range heads {
		// Oldest is iteratively computed below.
		candidates[i] = chain{Oldest: heads[i], Head: heads[i]}
	}
	// Not strictly necessary, but simplifies checks in tests.
	sort.Slice(candidates, func(i, j int) bool {
		ih, jh := candidates[i].Oldest.Hash(), candidates[j].Oldest.Hash()
		return bytes.Compare(ih[:], jh[:]) < 0
	})

	// candidates.Oldest needs to be computed by working backwards from
	// head as far as we can.
	iterAgain := true // if theres still work to be done.
	for i := 0; iterAgain; i++ {
		if i >= maxIter {
			return nil, fmt.Errorf("iteration limit exceeded (%d)", maxIter)
		}

		iterAgain = false
		for j := range candidates {
			parent, hasParent := candidates[j].Oldest.Parent()
			if hasParent {
				parent, err := storage.AUM(parent)
				if err != nil {
					if err == os.ErrNotExist {
						continue
					}
					return nil, fmt.Errorf("reading parent: %v", err)
				}
				candidates[j].Oldest = parent
				if lastKnownOldest != nil && *lastKnownOldest == parent.Hash() {
					candidates[j].chainsThroughActive = true
				}
				iterAgain = true
			}
		}
	}
	return candidates, nil
}

// pickNextAUM returns the AUM which should be used as the next
// AUM in the chain, possibly applying fork resolution logic.
//
// In other words: given an AUM with 3 children like this:
//
//	  / - 1
//	P   - 2
//	  \ - 3
//
// pickNextAUM will determine and return the correct branch.
//
// This method takes ownership of the provided slice.
func pickNextAUM(state State, candidates []AUM) AUM {
	switch len(candidates) {
	case 0:
		panic("pickNextAUM called with empty candidate set")
	case 1:
		return candidates[0]
	}

	// Oooof, we have some forks in the chain. We need to pick which
	// one to use by applying the Fork Resolution Algorithm ✨
	//
	// The rules are this:
	// 1. The child with the highest signature weight is chosen.
	// 2. If equal, the child which is a RemoveKey AUM is chosen.
	// 3. If equal, the child with the lowest AUM hash is chosen.
	sort.Slice(candidates, func(j, i int) bool {
		// Rule 1.
		iSigWeight, jSigWeight := candidates[i].Weight(state), candidates[j].Weight(state)
		if iSigWeight != jSigWeight {
			return iSigWeight < jSigWeight
		}

		// Rule 2.
		if iKind, jKind := candidates[i].MessageKind, candidates[j].MessageKind; iKind != jKind &&
			(iKind == AUMRemoveKey || jKind == AUMRemoveKey) {
			return jKind == AUMRemoveKey
		}

		// Rule 3.
		iHash, jHash := candidates[i].Hash(), candidates[j].Hash()
		return bytes.Compare(iHash[:], jHash[:]) > 0
	})

	return candidates[0]
}

// advanceByPrimary computes the next AUM to advance with based on
// deterministic fork-resolution rules. All nodes should apply this logic
// when computing the primary chain, hence achieving consensus on what the
// primary chain (and hence, the shared state) is.
//
// This method returns the chosen AUM & the state obtained by applying that
// AUM.
//
// The return value for next is nil if there are no children AUMs, hence
// the provided state is at head (up to date).
func advanceByPrimary(state State, candidates []AUM) (next *AUM, out State, err error) {
	if len(candidates) == 0 {
		return nil, state, nil
	}

	aum := pickNextAUM(state, candidates)

	if state, err = state.applyVerifiedAUM(aum); err != nil {
		return nil, State{}, fmt.Errorf("advancing state: %v", err)
	}
	return &aum, state, nil
}

// fastForwardWithAdvancer iteratively advances the current state by calling
// the given advancer to get+apply the next update. This process is repeated
// until the given termination function returns true or there is no more
// progress possible.
//
// The last-processed AUM, and the state computed after applying the last AUM,
// are returned.
func fastForwardWithAdvancer(
	storage Chonk, maxIter int, startState State,
	advancer func(state State, candidates []AUM) (next *AUM, out State, err error),
	done func(curAUM AUM, curState State) bool,
) (AUM, State, error) {
	if startState.LastAUMHash == nil {
		return AUM{}, State{}, errors.New("invalid initial state")
	}
	nextAUM, err := storage.AUM(*startState.LastAUMHash)
	if err != nil {
		return AUM{}, State{}, fmt.Errorf("reading next: %v", err)
	}

	curs := nextAUM
	state := startState
	for i := 0; i < maxIter; i++ {
		if done != nil && done(curs, state) {
			return curs, state, nil
		}

		children, err := storage.ChildAUMs(curs.Hash())
		if err != nil {
			return AUM{}, State{}, fmt.Errorf("getting children of %X: %v", curs.Hash(), err)
		}
		next, nextState, err := advancer(state, children)
		if err != nil {
			return AUM{}, State{}, fmt.Errorf("advance %X: %v", curs.Hash(), err)
		}
		if next == nil {
			// There were no more children, we are at 'head'.
			return curs, state, nil
		}
		curs = *next
		state = nextState
	}

	return AUM{}, State{}, fmt.Errorf("iteration limit exceeded (%d)", maxIter)
}

// fastForward iteratively advances the current state based on known AUMs until
// the given termination function returns true or there is no more progress possible.
//
// The last-processed AUM, and the state computed after applying the last AUM,
// are returned.
func fastForward(storage Chonk, maxIter int, startState State, done func(curAUM AUM, curState State) bool) (AUM, State, error) {
	return fastForwardWithAdvancer(storage, maxIter, startState, advanceByPrimary, done)
}

// computeStateAt returns the State at wantHash.
func computeStateAt(storage Chonk, maxIter int, wantHash AUMHash) (State, error) {
	topAUM, err := storage.AUM(wantHash)
	if err != nil {
		return State{}, err
	}

	// Iterate backwards till we find a starting point to compute
	// the state from.
	//
	// Valid starting points are either a checkpoint AUM, or a
	// genesis AUM.
	var (
		curs  = topAUM
		state State
		path  = make(set.Set[AUMHash], 32) // 32 chosen arbitrarily.
	)
	for i := 0; true; i++ {
		if i > maxIter {
			return State{}, fmt.Errorf("iteration limit exceeded (%d)", maxIter)
		}
		path.Add(curs.Hash())

		// Checkpoints encapsulate the state at that point, dope.
		if curs.MessageKind == AUMCheckpoint {
			state = curs.State.cloneForUpdate(&curs)
			break
		}
		parent, hasParent := curs.Parent()
		if !hasParent {
			// This is a 'genesis' update: there are none before it, so
			// this AUM can be applied to the empty state to determine
			// the state at this AUM.
			//
			// It is only valid for NoOp, AddKey, and Checkpoint AUMs
			// to be a genesis update. Checkpoint was handled earlier.
			if mk := curs.MessageKind; mk == AUMNoOp || mk == AUMAddKey {
				var err error
				if state, err = (State{}).applyVerifiedAUM(curs); err != nil {
					return State{}, fmt.Errorf("applying genesis (%+v): %v", curs, err)
				}
				break
			}
			return State{}, fmt.Errorf("invalid genesis update: %+v", curs)
		}

		// If we got here, the current state is dependent on the previous.
		// Keep iterating backwards till thats not the case.
		if curs, err = storage.AUM(parent); err != nil {
			return State{}, fmt.Errorf("reading parent: %v", err)
		}
	}

	// We now know some starting point state. Iterate forward till we
	// are at the AUM we want state for.
	//
	// We want to fast forward based on the path we took above, which
	// (in the case of a non-primary fork) may differ from a regular
	// fast-forward (which follows standard fork-resolution rules). As
	// such, we use a custom advancer here.
	advancer := func(state State, candidates []AUM) (next *AUM, out State, err error) {
		for _, c := range candidates {
			if path.Contains(c.Hash()) {
				if state, err = state.applyVerifiedAUM(c); err != nil {
					return nil, State{}, fmt.Errorf("advancing state: %v", err)
				}
				return &c, state, nil
			}
		}

		return nil, State{}, errors.New("no candidate matching path")
	}
	_, state, err = fastForwardWithAdvancer(storage, maxIter, state, advancer, func(curs AUM, _ State) bool {
		return curs.Hash() == wantHash
	})
	// fastForward only terminates before the done condition if it
	// doesnt have any later AUMs to process. This cant be the case
	// as we've already iterated through them above so they must exist,
	// but we check anyway to be super duper sure.
	if err == nil && *state.LastAUMHash != wantHash {
		return State{}, errors.New("unexpected fastForward outcome")
	}
	return state, err
}

// computeActiveAncestor determines which ancestor AUM to use as the
// ancestor of the valid chain.
//
// If all the chains end up having the same ancestor, then thats the
// only possible ancestor, ezpz. However if there are multiple distinct
// ancestors, that means there are distinct chains, and we need some
// hint to choose what to use. For that, we rely on the chainsThroughActive
// bit, which signals to us that that ancestor was part of the
// chain in a previous run.
func computeActiveAncestor(storage Chonk, chains []chain) (AUMHash, error) {
	// Dedupe possible ancestors, tracking if they were part of
	// the active chain on a previous run.
	ancestors := make(map[AUMHash]bool, len(chains))
	for _, c := range chains {
		ancestors[c.Oldest.Hash()] = c.chainsThroughActive
	}

	if len(ancestors) == 1 {
		// There's only one. DOPE.
		for k := range ancestors {
			return k, nil
		}
	}

	// Theres more than one, so we need to use the ancestor that was
	// part of the active chain in a previous iteration.
	// Note that there can only be one distinct ancestor that was
	// formerly part of the active chain, because AUMs can only have
	// one parent and would have converged to a common ancestor.
	for k, chainsThroughActive := range ancestors {
		if chainsThroughActive {
			return k, nil
		}
	}

	return AUMHash{}, errors.New("multiple distinct chains")
}

// computeActiveChain bootstraps the runtime state of the Authority when
// starting entirely off stored state.
//
// TODO(tom): Don't look at head states, just iterate forward from
// the ancestor.
//
// The algorithm is as follows:
//  1. Determine all possible 'head' (like in git) states.
//  2. Filter these possible chains based on whether the ancestor was
//     formerly (in a previous run) part of the chain.
//  3. Compute the state of the state machine at this ancestor. This is
//     needed for fast-forward, as each update operates on the state of
//     the update preceding it.
//  4. Iteratively apply updates till we reach head ('fast forward').
func computeActiveChain(storage Chonk, lastKnownOldest *AUMHash, maxIter int) (chain, error) {
	chains, err := computeChainCandidates(storage, lastKnownOldest, maxIter)
	if err != nil {
		return chain{}, fmt.Errorf("computing candidates: %v", err)
	}

	// Find the right ancestor.
	oldestHash, err := computeActiveAncestor(storage, chains)
	if err != nil {
		return chain{}, fmt.Errorf("computing ancestor: %v", err)
	}
	ancestor, err := storage.AUM(oldestHash)
	if err != nil {
		return chain{}, err
	}

	// At this stage we know the ancestor AUM, so we have excluded distinct
	// chains but we might still have forks (so we don't know the head AUM).
	//
	// We iterate forward from the ancestor AUM, handling any forks as we go
	// till we arrive at a head.
	out := chain{Oldest: ancestor, Head: ancestor}
	if out.state, err = computeStateAt(storage, maxIter, oldestHash); err != nil {
		return chain{}, fmt.Errorf("bootstrapping state: %v", err)
	}
	out.Head, out.state, err = fastForward(storage, maxIter, out.state, nil)
	if err != nil {
		return chain{}, fmt.Errorf("fast forward: %v", err)
	}
	return out, nil
}

// aumVerify verifies if an AUM is well-formed, correctly signed, and
// can be accepted for storage.
func aumVerify(aum AUM, state State, isGenesisAUM bool) error {
	if err := aum.StaticValidate(); err != nil {
		return fmt.Errorf("invalid: %v", err)
	}
	if !isGenesisAUM {
		if err := checkParent(aum, state); err != nil {
			return err
		}
	}

	if len(aum.Signatures) == 0 {
		return errors.New("unsigned AUM")
	}
	sigHash := aum.SigHash()
	for i, sig := range aum.Signatures {
		key, err := state.GetKey(sig.KeyID)
		if err != nil {
			return fmt.Errorf("bad keyID on signature %d: %v", i, err)
		}
		if err := signatureVerify(&sig, sigHash, key); err != nil {
			return fmt.Errorf("signature %d: %v", i, err)
		}
	}
	return nil
}

func checkParent(aum AUM, state State) error {
	parent, hasParent := aum.Parent()
	if !hasParent {
		return errors.New("aum has no parent")
	}
	if state.LastAUMHash == nil {
		return errors.New("cannot check update parent hash against a state with no previous AUM")
	}
	if *state.LastAUMHash != parent {
		return fmt.Errorf("aum with parent %x cannot be applied to a state with parent %x", state.LastAUMHash, parent)
	}
	return nil
}

// Head returns the AUM digest of the latest update applied to the state
// machine.
func (a *Authority) Head() AUMHash {
	return *a.state.LastAUMHash
}

// Open initializes an existing TKA from the given tailchonk.
//
// Only use this if the current node has initialized an Authority before.
// If a TKA exists on other nodes but theres nothing locally, use Bootstrap().
// If no TKA exists anywhere and you are creating it for the first
// time, use New().
func Open(storage Chonk) (*Authority, error) {
	a, err := storage.LastActiveAncestor()
	if err != nil {
		return nil, fmt.Errorf("reading last ancestor: %v", err)
	}

	c, err := computeActiveChain(storage, a, maxScanIterations)
	if err != nil {
		return nil, fmt.Errorf("active chain: %v", err)
	}

	return &Authority{
		head:           c.Head,
		oldestAncestor: c.Oldest,
		state:          c.state,
	}, nil
}

// Create initializes a brand-new TKA, generating a genesis update
// and committing it to the given storage.
//
// The given signer must also be present in state as a trusted key.
//
// Do not use this to initialize a TKA that already exists, use Open()
// or Bootstrap() instead.
func Create(storage Chonk, state State, signer Signer) (*Authority, AUM, error) {
	// Generate & sign a checkpoint, our genesis update.
	genesis := AUM{
		MessageKind: AUMCheckpoint,
		State:       &state,
	}
	if err := genesis.StaticValidate(); err != nil {
		// This serves as an easy way to validate the given state.
		return nil, AUM{}, fmt.Errorf("invalid state: %v", err)
	}
	sigs, err := signer.SignAUM(genesis.SigHash())
	if err != nil {
		return nil, AUM{}, fmt.Errorf("signing failed: %v", err)
	}
	genesis.Signatures = append(genesis.Signatures, sigs...)

	a, err := Bootstrap(storage, genesis)
	return a, genesis, err
}

// Bootstrap initializes a TKA based on the given checkpoint.
//
// Call this when setting up a new nodes' TKA, but other nodes
// with initialized TKA's exist.
//
// Pass the returned genesis AUM from Create(), or a later checkpoint AUM.
//
// TODO(tom): We should test an authority bootstrapped from a later checkpoint
// works fine with sync and everything.
func Bootstrap(storage Chonk, bootstrap AUM) (*Authority, error) {
	heads, err := storage.Heads()
	if err != nil {
		return nil, fmt.Errorf("reading heads: %v", err)
	}
	if len(heads) != 0 {
		return nil, errors.New("tailchonk is not empty")
	}

	// Check the AUM is well-formed.
	if bootstrap.MessageKind != AUMCheckpoint {
		return nil, fmt.Errorf("bootstrap AUMs must be checkpoint messages, got %v", bootstrap.MessageKind)
	}
	if bootstrap.State == nil {
		return nil, errors.New("bootstrap AUM is missing state")
	}
	if err := aumVerify(bootstrap, *bootstrap.State, true); err != nil {
		return nil, fmt.Errorf("invalid bootstrap: %v", err)
	}

	// Everything looks good, write it to storage.
	if err := storage.CommitVerifiedAUMs([]AUM{bootstrap}); err != nil {
		return nil, fmt.Errorf("commit: %v", err)
	}
	if err := storage.SetLastActiveAncestor(bootstrap.Hash()); err != nil {
		return nil, fmt.Errorf("set ancestor: %v", err)
	}

	return Open(storage)
}

// ValidDisablement returns true if the disablement secret was correct.
//
// If this method returns true, the caller should shut down the authority
// and purge all network-lock state.
func (a *Authority) ValidDisablement(secret []byte) bool {
	return a.state.checkDisablement(secret)
}

// InformIdempotent returns a new Authority based on applying the given
// updates, with the given updates committed to storage.
//
// If any of the updates could not be applied:
//   - An error is returned
//   - No changes to storage are made.
//
// MissingAUMs() should be used to get a list of updates appropriate for
// this function. In any case, updates should be ordered oldest to newest.
func (a *Authority) InformIdempotent(storage Chonk, updates []AUM) (Authority, error) {
	if len(updates) == 0 {
		return Authority{}, errors.New("inform called with empty slice")
	}
	stateAt := make(map[AUMHash]State, len(updates)+1)
	toCommit := make([]AUM, 0, len(updates))
	prevHash := a.Head()

	// The state at HEAD is the current state of the authority. Its likely
	// to be needed, so we prefill it rather than computing it.
	stateAt[prevHash] = a.state

	// Optimization: If the set of updates is a chain building from
	// the current head, EG:
	//   <a.Head()> ==> updates[0] ==> updates[1] ...
	// Then theres no need to recompute the resulting state from the
	// stored ancestor, because the last state computed during iteration
	// is the new state. This should be the common case.
	// isHeadChain keeps track of this.
	isHeadChain := true

	for i, update := range updates {
		hash := update.Hash()
		// Check if we already have this AUM thus don't need to process it.
		if _, err := storage.AUM(hash); err == nil {
			isHeadChain = false // Disable the head-chain optimization.
			continue
		}

		parent, hasParent := update.Parent()
		if !hasParent {
			return Authority{}, fmt.Errorf("update %d: missing parent", i)
		}

		state, hasState := stateAt[parent]
		var err error
		if !hasState {
			if state, err = computeStateAt(storage, maxScanIterations, parent); err != nil {
				return Authority{}, fmt.Errorf("update %d computing state: %v", i, err)
			}
			stateAt[parent] = state
		}

		if err := aumVerify(update, state, false); err != nil {
			return Authority{}, fmt.Errorf("update %d invalid: %v", i, err)
		}
		if stateAt[hash], err = state.applyVerifiedAUM(update); err != nil {
			return Authority{}, fmt.Errorf("update %d cannot be applied: %v", i, err)
		}

		if isHeadChain && parent != prevHash {
			isHeadChain = false
		}
		prevHash = hash
		toCommit = append(toCommit, update)
	}

	if err := storage.CommitVerifiedAUMs(toCommit); err != nil {
		return Authority{}, fmt.Errorf("commit: %v", err)
	}

	if isHeadChain {
		// Head-chain fastpath: We can use the state we computed
		// in the last iteration.
		return Authority{
			head:           updates[len(updates)-1],
			oldestAncestor: a.oldestAncestor,
			state:          stateAt[prevHash],
		}, nil
	}

	oldestAncestor := a.oldestAncestor.Hash()
	c, err := computeActiveChain(storage, &oldestAncestor, maxScanIterations)
	if err != nil {
		return Authority{}, fmt.Errorf("recomputing active chain: %v", err)
	}
	return Authority{
		head:           c.Head,
		oldestAncestor: c.Oldest,
		state:          c.state,
	}, nil
}

// Inform is the same as InformIdempotent, except the state of the Authority
// is updated in-place.
func (a *Authority) Inform(storage Chonk, updates []AUM) error {
	newAuthority, err := a.InformIdempotent(storage, updates)
	if err != nil {
		return err
	}
	*a = newAuthority
	return nil
}

// NodeKeyAuthorized checks if the provided nodeKeySignature authorizes
// the given node key.
func (a *Authority) NodeKeyAuthorized(nodeKey key.NodePublic, nodeKeySignature tkatype.MarshaledSignature) error {
	var decoded NodeKeySignature
	if err := decoded.Unserialize(nodeKeySignature); err != nil {
		return fmt.Errorf("unserialize: %v", err)
	}
	if decoded.SigKind == SigCredential {
		return errors.New("credential signatures cannot authorize nodes on their own")
	}

	kID, err := decoded.authorizingKeyID()
	if err != nil {
		return err
	}

	key, err := a.state.GetKey(kID)
	if err != nil {
		return fmt.Errorf("key: %v", err)
	}

	return decoded.verifySignature(nodeKey, key)
}

// KeyTrusted returns true if the given keyID is trusted by the tailnet
// key authority.
func (a *Authority) KeyTrusted(keyID tkatype.KeyID) bool {
	_, err := a.state.GetKey(keyID)
	return err == nil
}

// Keys returns the set of keys trusted by the tailnet key authority.
func (a *Authority) Keys() []Key {
	out := make([]Key, len(a.state.Keys))
	for i := range a.state.Keys {
		out[i] = a.state.Keys[i].Clone()
	}
	return out
}

// StateIDs returns the stateIDs for this tailnet key authority. These
// are values that are fixed for the lifetime of the authority: see
// comments on the relevant fields in state.go.
func (a *Authority) StateIDs() (uint64, uint64) {
	return a.state.StateID1, a.state.StateID2
}

// Compact deletes historical AUMs based on the given compaction options.
func (a *Authority) Compact(storage CompactableChonk, o CompactionOptions) error {
	newAncestor, err := Compact(storage, a.head.Hash(), o)
	if err != nil {
		return err
	}
	ancestor, err := storage.AUM(newAncestor)
	if err != nil {
		return err
	}
	a.oldestAncestor = ancestor
	return nil
}

// findParentForRewrite finds the parent AUM to use when rewriting state to
// retroactively remove trust in the specified keys.
func (a *Authority) findParentForRewrite(storage Chonk, removeKeys []tkatype.KeyID, ourKey tkatype.KeyID) (AUMHash, error) {
	cursor := a.Head()

	for {
		if cursor == a.oldestAncestor.Hash() {
			// We've reached as far back in our history as we can,
			// so we have to rewrite from here.
			break
		}

		aum, err := storage.AUM(cursor)
		if err != nil {
			return AUMHash{}, fmt.Errorf("reading AUM %v: %w", cursor, err)
		}

		// An ideal rewrite parent trusts none of the keys to be removed.
		state, err := computeStateAt(storage, maxScanIterations, cursor)
		if err != nil {
			return AUMHash{}, fmt.Errorf("computing state for %v: %w", cursor, err)
		}
		keyTrusted := false
		for _, key := range removeKeys {
			if _, err := state.GetKey(key); err == nil {
				keyTrusted = true
			}
		}
		if !keyTrusted {
			// Success: the revoked keys are not trusted!
			// Lets check that our key was trusted to ensure
			// we can sign a fork from here.
			if _, err := state.GetKey(ourKey); err == nil {
				break
			}
		}

		parent, hasParent := aum.Parent()
		if !hasParent {
			// This is the genesis AUM, so we have to rewrite from here.
			break
		}
		cursor = parent
	}

	return cursor, nil
}

// MakeRetroactiveRevocation generates a forking update which revokes the specified keys, in
// such a manner that any malicious use of those keys is erased.
//
// If forkFrom is specified, it is used as the parent AUM to fork from. If the zero value,
// the parent AUM is determined automatically.
//
// The generated AUM must be signed with more signatures than the sum of key votes that
// were compromised, before being consumed by tka.Authority methods.
func (a *Authority) MakeRetroactiveRevocation(storage Chonk, removeKeys []tkatype.KeyID, ourKey tkatype.KeyID, forkFrom AUMHash) (*AUM, error) {
	var parent AUMHash
	if forkFrom == (AUMHash{}) {
		// Make sure at least one of the recovery keys is currently trusted.
		foundKey := false
		for _, k := range removeKeys {
			if _, err := a.state.GetKey(k); err == nil {
				foundKey = true
				break
			}
		}
		if !foundKey {
			return nil, errors.New("no provided key is currently trusted")
		}

		p, err := a.findParentForRewrite(storage, removeKeys, ourKey)
		if err != nil {
			return nil, fmt.Errorf("finding parent: %v", err)
		}
		parent = p
	} else {
		parent = forkFrom
	}

	// Construct the new state where the revoked keys are no longer trusted.
	state := a.state.Clone()
	for _, keyToRevoke := range removeKeys {
		idx := -1
		for i := range state.Keys {
			keyID, err := state.Keys[i].ID()
			if err != nil {
				return nil, fmt.Errorf("computing keyID: %v", err)
			}
			if bytes.Equal(keyToRevoke, keyID) {
				idx = i
				break
			}
		}
		if idx >= 0 {
			state.Keys = append(state.Keys[:idx], state.Keys[idx+1:]...)
		}
	}
	if len(state.Keys) == 0 {
		return nil, errors.New("cannot revoke all trusted keys")
	}
	state.LastAUMHash = nil // checkpoints can't specify a LastAUMHash

	forkingAUM := &AUM{
		MessageKind: AUMCheckpoint,
		State:       &state,
		PrevAUMHash: parent[:],
	}

	return forkingAUM, forkingAUM.StaticValidate()
}

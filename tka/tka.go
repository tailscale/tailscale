// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tka (WIP) implements the Tailnet Key Authority.
package tka

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
)

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
//    / - 1
//  P   - 2
//    \ - 3
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

// advanceChain computes the next AUM to advance with based on all child
// AUMs, returning the chosen AUM & the state obtained by applying that
// AUM.
//
// The return value for next is nil if there are no children AUMs, hence
// the provided state is at head (up to date).
func advanceChain(state State, candidates []AUM) (next *AUM, out State, err error) {
	if len(candidates) == 0 {
		return nil, state, nil
	}

	aum := pickNextAUM(state, candidates)
	if state, err = state.applyVerifiedAUM(aum); err != nil {
		return nil, State{}, fmt.Errorf("advancing state: %v", err)
	}
	return &aum, state, nil
}

// fastForward iteratively advances the current state based on known AUMs until
// the given termination function returns true or there is no more progress possible.
//
// The last-processed AUM, and the state computed after applying the last AUM,
// are returned.
func fastForward(storage Chonk, maxIter int, startState State, done func(curAUM AUM, curState State) bool) (AUM, State, error) {
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
		next, nextState, err := advanceChain(state, children)
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

// computeStateAt returns the State at wantHash.
func computeStateAt(storage Chonk, maxIter int, wantHash AUMHash) (State, error) {
	// TODO(tom): This is going to get expensive for really long
	//            chains. We should make nodes emit a checkpoint every
	//            X updates or something.

	topAUM, err := storage.AUM(wantHash)
	if err != nil {
		return State{}, err
	}

	// Iterate backwards till we find a starting point to compute
	// the state from.
	//
	// Valid starting points are either a checkpoint AUM, or a
	// genesis AUM.
	curs := topAUM
	var state State
	for i := 0; true; i++ {
		if i > maxIter {
			return State{}, fmt.Errorf("iteration limit exceeded (%d)", maxIter)
		}

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
	_, state, err = fastForward(storage, maxIter, state, func(curs AUM, _ State) bool {
		return curs.Hash() == wantHash
	})
	// fastForward only terminates before the done condition if it
	// doesnt have any later AUMs to process. This cant be the case
	// as we've already iterated through them above so they must exist,
	// but we check anyway to be super duper sure.
	if err == nil && *state.LastAUMHash != wantHash {
		panic("unexpected fastForward outcome")
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
		for k, _ := range ancestors {
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
// 1. Determine all possible 'head' (like in git) states.
// 2. Filter these possible chains based on whether the ancestor was
//    formerly (in a previous run) part of the chain.
// 3. Compute the state of the state machine at this ancestor. This is
//    needed for fast-forward, as each update operates on the state of
//    the update preceeding it.
// 4. Iteratively apply updates till we reach head ('fast forward').
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

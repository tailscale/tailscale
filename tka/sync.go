// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"errors"
	"fmt"
	"os"
)

const (
	// Max iterations searching for any intersection.
	maxSyncIter = 2000
	// Max iterations searching for a head intersection.
	maxSyncHeadIntersectionIter = 400
)

// ErrNoIntersection is returned when a shared AUM could
// not be determined when evaluating a remote sync offer.
var ErrNoIntersection = errors.New("no intersection")

// SyncOffer conveys information about the current head & ancestor AUMs,
// for the purpose of synchronization with some remote end.
//
// Ancestors should contain a subset of the ancestors of the chain.
// The last entry in that slice is the oldest-known AUM in the chain.
type SyncOffer struct {
	Head      AUMHash
	Ancestors []AUMHash
}

const (
	// The starting number of AUMs to skip when listing
	// ancestors in a SyncOffer.
	ancestorsSkipStart = 4

	// How many bits to advance the skip count when listing
	// ancestors in a SyncOffer.
	//
	// 2 bits, so (4<<2), so after skipping 4 it skips 16.
	ancestorsSkipShift = 2
)

// SyncOffer returns an abbreviated description of the current AUM
// chain, which can be used to synchronize with another (untrusted)
// Authority instance.
//
// The returned SyncOffer structure should be transmitted to the remote
// Authority, which should call MissingAUMs() using it to determine
// AUMs which need to be transmitted. This list of AUMs from the remote
// can then be applied locally with Inform().
//
// This SyncOffer + AUM exchange should be performed by both ends,
// because its possible that either end has AUMs that the other needs
// to find out about.
func (a *Authority) SyncOffer(storage Chonk) (SyncOffer, error) {
	oldest := a.oldestAncestor.Hash()

	out := SyncOffer{
		Head:      a.Head(),
		Ancestors: make([]AUMHash, 0, 6), // 6 chosen arbitrarily.
	}

	// We send some subset of our ancestors to help the remote
	// find a more-recent 'head intersection'.
	// The number of AUMs between each ancestor entry gets
	// exponentially larger.
	var (
		skipAmount uint64  = ancestorsSkipStart
		curs       AUMHash = a.Head()
	)
	for i := uint64(0); i < maxSyncHeadIntersectionIter; i++ {
		if i > 0 && (i%skipAmount) == 0 {
			out.Ancestors = append(out.Ancestors, curs)
			skipAmount = skipAmount << ancestorsSkipShift
		}

		parent, err := storage.AUM(curs)
		if err != nil {
			if err != os.ErrNotExist {
				return SyncOffer{}, err
			}
			break
		}

		// We add the oldest later on, so don't duplicate.
		if parent.Hash() == oldest {
			break
		}
		copy(curs[:], parent.PrevAUMHash)
	}

	out.Ancestors = append(out.Ancestors, oldest)
	return out, nil
}

// intersection describes how to synchronize AUMs with a remote
// authority.
type intersection struct {
	// if true, no exchange of AUMs is needed.
	upToDate bool

	// headIntersection is the latest common AUM on the remote. In other
	// words, we need to send all AUMs since this one.
	headIntersection *AUMHash

	// tailIntersection is the oldest common AUM on the remote. In other
	// words, we diverge with the remote after this AUM, so we both need
	// to transmit our AUM chain starting here.
	tailIntersection *AUMHash
}

// computeSyncIntersection determines the common AUMs between a local and
// remote SyncOffer. This intersection can be used to synchronize both
// sides.
func computeSyncIntersection(storage Chonk, localOffer, remoteOffer SyncOffer) (*intersection, error) {
	// Simple case: up to date.
	if remoteOffer.Head == localOffer.Head {
		return &intersection{upToDate: true, headIntersection: &localOffer.Head}, nil
	}

	// Case: 'head intersection'
	// If we have the remote's head, its more likely than not that
	// we have updates that build on that head. To confirm this,
	// we iterate backwards through our chain to see if the given
	// head is an ancestor of our current chain.
	//
	// In other words:
	// <Us>   A -> B -> C
	// <Them> A -> B
	//   ∴ their head intersects with our chain, we need to send C
	var hasRemoteHead bool
	_, err := storage.AUM(remoteOffer.Head)
	if err != nil {
		if err != os.ErrNotExist {
			return nil, err
		}
	} else {
		hasRemoteHead = true
	}

	if hasRemoteHead {
		curs := localOffer.Head
		for i := 0; i < maxSyncHeadIntersectionIter; i++ {
			parent, err := storage.AUM(curs)
			if err != nil {
				if err != os.ErrNotExist {
					return nil, err
				}
				break
			}

			if parent.Hash() == remoteOffer.Head {
				h := parent.Hash()
				return &intersection{headIntersection: &h}, nil
			}

			copy(curs[:], parent.PrevAUMHash)
		}
	}

	// Case: 'tail intersection'
	// So we don't have a clue what the remote's head is, but
	// if one of the ancestors they gave us is part of our chain,
	// then theres an intersection, which is a starting point for
	// the remote to send us AUMs from.
	//
	// We iterate the list of ancestors in order because the remote
	// ordered them such that the newer ones are earlier, so with
	// a bit of luck we can use an earlier one and hence do less work /
	// transmit fewer AUMs.
	for _, a := range remoteOffer.Ancestors {
		state, err := computeStateAt(storage, maxSyncIter, a)
		if err != nil {
			if err != os.ErrNotExist {
				return nil, fmt.Errorf("computeStateAt: %v", err)
			}
			continue
		}

		end, _, err := fastForward(storage, maxSyncIter, state, func(curs AUM, _ State) bool {
			return curs.Hash() == localOffer.Head
		})
		if err != nil {
			return nil, err
		}
		// fastForward can terminate before the done condition if there are
		// no more children left, so we check again before considering this
		// an intersection.
		if end.Hash() == localOffer.Head {
			return &intersection{tailIntersection: &a}, nil
		}
	}

	return nil, ErrNoIntersection
}

// MissingAUMs returns AUMs a remote may be missing based on the
// remotes' SyncOffer.
func (a *Authority) MissingAUMs(storage Chonk, remoteOffer SyncOffer) ([]AUM, error) {
	localOffer, err := a.SyncOffer(storage)
	if err != nil {
		return nil, fmt.Errorf("local syncOffer: %v", err)
	}
	intersection, err := computeSyncIntersection(storage, localOffer, remoteOffer)
	if err != nil {
		return nil, fmt.Errorf("intersection: %v", err)
	}
	if intersection.upToDate {
		return nil, nil
	}
	out := make([]AUM, 0, 12) // 12 chosen arbitrarily.

	if intersection.headIntersection != nil {
		state, err := computeStateAt(storage, maxSyncIter, *intersection.headIntersection)
		if err != nil {
			return nil, err
		}

		_, _, err = fastForward(storage, maxSyncIter, state, func(curs AUM, _ State) bool {
			if curs.Hash() != *intersection.headIntersection {
				out = append(out, curs)
			}
			return false
		})
		return out, err
	}

	if intersection.tailIntersection != nil {
		state, err := computeStateAt(storage, maxSyncIter, *intersection.tailIntersection)
		if err != nil {
			return nil, err
		}

		_, _, err = fastForward(storage, maxSyncIter, state, func(curs AUM, _ State) bool {
			if curs.Hash() != *intersection.tailIntersection {
				out = append(out, curs)
			}
			return false
		})
		return out, err
	}

	panic("unreachable")
}

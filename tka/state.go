// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"tailscale.com/types/tkatype"
)

// ErrNoSuchKey is returned if the key referenced by a KeyID does not exist.
var ErrNoSuchKey = errors.New("key not found")

// State describes Tailnet Key Authority state at an instant in time.
//
// State is mutated by applying Authority Update Messages (AUMs), resulting
// in a new State.
type State struct {
	// LastAUMHash is the blake2s digest of the last-applied AUM.
	// Because AUMs are strictly ordered and form a hash chain, we
	// check the previous AUM hash in an update we are applying
	// is the same as the LastAUMHash.
	LastAUMHash *AUMHash `cbor:"1,keyasint"`

	// DisablementSecrets are KDF-derived values which can be used
	// to turn off the TKA in the event of a consensus-breaking bug.
	DisablementSecrets [][]byte `cbor:"2,keyasint"`

	// Keys are the public keys of either:
	//
	//   1. The signing nodes currently trusted by the TKA.
	//   2. Ephemeral keys that were used to generate pre-signed auth keys.
	Keys []Key `cbor:"3,keyasint"`

	// StateID's are nonce's, generated on enablement and fixed for
	// the lifetime of the Tailnet Key Authority. We generate 16-bytes
	// worth of keyspace here just in case we come up with a cool future
	// use for this.
	StateID1 uint64 `cbor:"4,keyasint,omitempty"`
	StateID2 uint64 `cbor:"5,keyasint,omitempty"`
}

// GetKey returns the trusted key with the specified KeyID.
func (s State) GetKey(key tkatype.KeyID) (Key, error) {
	for _, k := range s.Keys {
		keyID, err := k.ID()
		if err != nil {
			return Key{}, err
		}

		if bytes.Equal(keyID, key) {
			return k, nil
		}
	}

	return Key{}, ErrNoSuchKey
}

// Clone makes an independent copy of State.
//
// NOTE: There is a difference between a nil slice and an empty
// slice for encoding purposes, so an implementation of Clone()
// must take care to preserve this.
func (s State) Clone() State {
	out := State{
		StateID1: s.StateID1,
		StateID2: s.StateID2,
	}

	if s.LastAUMHash != nil {
		dupe := *s.LastAUMHash
		out.LastAUMHash = &dupe
	}

	if s.DisablementSecrets != nil {
		out.DisablementSecrets = make([][]byte, len(s.DisablementSecrets))
		for i := range s.DisablementSecrets {
			out.DisablementSecrets[i] = make([]byte, len(s.DisablementSecrets[i]))
			copy(out.DisablementSecrets[i], s.DisablementSecrets[i])
		}
	}

	if s.Keys != nil {
		out.Keys = make([]Key, len(s.Keys))
		for i := range s.Keys {
			out.Keys[i] = s.Keys[i].Clone()
		}
	}

	return out
}

// cloneForUpdate is like Clone, except LastAUMHash is set based
// on the hash of the given update.
func (s State) cloneForUpdate(update *AUM) State {
	out := s.Clone()
	aumHash := update.Hash()
	out.LastAUMHash = &aumHash
	return out
}

const disablementLength = 32

var disablementSalt = []byte("tailscale network-lock disablement salt")

// DisablementKDF computes a public value which can be stored in a
// key authority, but cannot be reversed to find the input secret.
//
// When the output of this function is stored in tka state (i.e. in
// tka.State.DisablementSecrets) a call to Authority.ValidDisablement()
// with the input of this function as the argument will return true.
func DisablementKDF(secret []byte) []byte {
	// time = 4 (3 recommended, booped to 4 to compensate for less memory)
	// memory = 16 (32 recommended)
	// threads = 4
	// keyLen = 32 (256 bits)
	return argon2.Key(secret, disablementSalt, 4, 16*1024, 4, disablementLength)
}

// checkDisablement returns true for a valid disablement secret.
func (s State) checkDisablement(secret []byte) bool {
	derived := DisablementKDF(secret)
	for _, candidate := range s.DisablementSecrets {
		if bytes.Equal(derived, candidate) {
			return true
		}
	}
	return false
}

// parentMatches returns true if an AUM can chain to (be applied)
// to the current state.
//
// Specifically, the rules are:
//   - The last AUM hash must match (transitively, this implies that this
//     update follows the last update message applied to the state machine)
//   - Or, the state machine knows no parent (its brand new).
func (s State) parentMatches(update AUM) bool {
	if s.LastAUMHash == nil {
		return true
	}
	return bytes.Equal(s.LastAUMHash[:], update.PrevAUMHash)
}

// applyVerifiedAUM computes a new state based on the update provided.
//
// The provided update MUST be verified: That is, the AUM must be well-formed
// (as defined by StaticValidate()), and signatures over the AUM must have
// been verified.
func (s State) applyVerifiedAUM(update AUM) (State, error) {
	// Validate that the update message has the right parent.
	if !s.parentMatches(update) {
		return State{}, errors.New("parent AUMHash mismatch")
	}

	switch update.MessageKind {
	case AUMNoOp:
		out := s.cloneForUpdate(&update)
		return out, nil

	case AUMCheckpoint:
		if update.State == nil {
			return State{}, errors.New("missing checkpoint state")
		}
		id1Match, id2Match := update.State.StateID1 == s.StateID1, update.State.StateID2 == s.StateID2
		if !id1Match || !id2Match {
			return State{}, errors.New("checkpointed state has an incorrect stateID")
		}
		return update.State.cloneForUpdate(&update), nil

	case AUMAddKey:
		if update.Key == nil {
			return State{}, errors.New("no key to add provided")
		}
		keyID, err := update.Key.ID()
		if err != nil {
			return State{}, err
		}
		if _, err := s.GetKey(keyID); err == nil {
			return State{}, errors.New("key already exists")
		}
		out := s.cloneForUpdate(&update)
		out.Keys = append(out.Keys, *update.Key)
		return out, nil

	case AUMUpdateKey:
		k, err := s.GetKey(update.KeyID)
		if err != nil {
			return State{}, err
		}
		if update.Votes != nil {
			k.Votes = *update.Votes
		}
		if update.Meta != nil {
			k.Meta = update.Meta
		}
		if err := k.StaticValidate(); err != nil {
			return State{}, fmt.Errorf("updated key fails validation: %v", err)
		}
		out := s.cloneForUpdate(&update)
		for i := range out.Keys {
			keyID, err := out.Keys[i].ID()
			if err != nil {
				return State{}, err
			}
			if bytes.Equal(keyID, update.KeyID) {
				out.Keys[i] = k
			}
		}
		return out, nil

	case AUMRemoveKey:
		idx := -1
		for i := range s.Keys {
			keyID, err := s.Keys[i].ID()
			if err != nil {
				return State{}, err
			}
			if bytes.Equal(update.KeyID, keyID) {
				idx = i
				break
			}
		}
		if idx < 0 {
			return State{}, ErrNoSuchKey
		}
		out := s.cloneForUpdate(&update)
		out.Keys = append(out.Keys[:idx], out.Keys[idx+1:]...)
		return out, nil

	default:
		// An AUM with an unknown message kind was received! That means
		// that a future version of tailscaled added some feature we don't
		// understand.
		//
		// The future-compatibility contract for AUM message types is that
		// they must only add new features, not change the semantics of existing
		// mechanisms or features. As such, old clients can safely ignore them.
		out := s.cloneForUpdate(&update)
		return out, nil
	}
}

// Upper bound on checkpoint elements, chosen arbitrarily. Intended to
// cap out insanely large AUMs.
const (
	maxDisablementSecrets = 32
	maxKeys               = 512
)

// staticValidateCheckpoint validates that the state is well-formed for
// inclusion in a checkpoint AUM.
func (s *State) staticValidateCheckpoint() error {
	if s.LastAUMHash != nil {
		return errors.New("cannot specify a parent AUM")
	}
	if len(s.DisablementSecrets) == 0 {
		return errors.New("at least one disablement secret required")
	}
	if numDS := len(s.DisablementSecrets); numDS > maxDisablementSecrets {
		return fmt.Errorf("too many disablement secrets (%d, max %d)", numDS, maxDisablementSecrets)
	}
	for i, ds := range s.DisablementSecrets {
		if len(ds) != disablementLength {
			return fmt.Errorf("disablement[%d]: invalid length (got %d, want %d)", i, len(ds), disablementLength)
		}
		for j, ds2 := range s.DisablementSecrets {
			if i == j {
				continue
			}
			if bytes.Equal(ds, ds2) {
				return fmt.Errorf("disablement[%d]: duplicates disablement[%d]", i, j)
			}
		}
	}

	if len(s.Keys) == 0 {
		return errors.New("at least one key is required")
	}
	if numKeys := len(s.Keys); numKeys > maxKeys {
		return fmt.Errorf("too many keys (%d, max %d)", numKeys, maxKeys)
	}
	for i, k := range s.Keys {
		if err := k.StaticValidate(); err != nil {
			return fmt.Errorf("key[%d]: %v", i, err)
		}
	}
	// NOTE: The max number of keys is constrained (512), so
	// O(n^2) is fine.
	for i, k := range s.Keys {
		for j, k2 := range s.Keys {
			if i == j {
				continue
			}

			id1, err := k.ID()
			if err != nil {
				return fmt.Errorf("key[%d]: %w", i, err)
			}
			id2, err := k2.ID()
			if err != nil {
				return fmt.Errorf("key[%d]: %w", j, err)
			}

			if bytes.Equal(id1, id2) {
				return fmt.Errorf("key[%d]: duplicates key[%d]", i, j)
			}
		}
	}
	return nil
}

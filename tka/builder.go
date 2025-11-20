// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package tka

import (
	"fmt"
	"os"

	"tailscale.com/types/tkatype"
)

// Types implementing Signer can sign update messages.
type Signer interface {
	// SignAUM returns signatures for the AUM encoded by the given AUMSigHash.
	SignAUM(tkatype.AUMSigHash) ([]tkatype.Signature, error)
}

// UpdateBuilder implements a builder for changes to the tailnet
// key authority.
//
// Finalize must be called to compute the update messages, which
// must then be applied to all Authority objects using Inform().
type UpdateBuilder struct {
	a      *Authority
	signer Signer

	state  State
	parent AUMHash

	out []AUM
}

func (b *UpdateBuilder) mkUpdate(update AUM) error {
	prevHash := make([]byte, len(b.parent))
	copy(prevHash, b.parent[:])
	update.PrevAUMHash = prevHash

	if b.signer != nil {
		sigs, err := b.signer.SignAUM(update.SigHash())
		if err != nil {
			return fmt.Errorf("signing failed: %v", err)
		}
		update.Signatures = append(update.Signatures, sigs...)
	}
	if err := update.StaticValidate(); err != nil {
		return fmt.Errorf("generated update was invalid: %v", err)
	}
	state, err := b.state.applyVerifiedAUM(update)
	if err != nil {
		return fmt.Errorf("update cannot be applied: %v", err)
	}

	b.state = state
	b.parent = update.Hash()
	b.out = append(b.out, update)
	return nil
}

// AddKey adds a new key to the authority.
func (b *UpdateBuilder) AddKey(key Key) error {
	keyID, err := key.ID()
	if err != nil {
		return err
	}

	if _, err := b.state.GetKey(keyID); err == nil {
		return fmt.Errorf("cannot add key %v: already exists", key)
	}

	if len(b.state.Keys) >= maxKeys {
		return fmt.Errorf("cannot add key %v: maximum number of keys reached", key)
	}

	return b.mkUpdate(AUM{MessageKind: AUMAddKey, Key: &key})
}

// RemoveKey removes a key from the authority.
func (b *UpdateBuilder) RemoveKey(keyID tkatype.KeyID) error {
	if _, err := b.state.GetKey(keyID); err != nil {
		return fmt.Errorf("failed reading key %x: %v", keyID, err)
	}
	return b.mkUpdate(AUM{MessageKind: AUMRemoveKey, KeyID: keyID})
}

// SetKeyVote updates the number of votes of an existing key.
func (b *UpdateBuilder) SetKeyVote(keyID tkatype.KeyID, votes uint) error {
	if _, err := b.state.GetKey(keyID); err != nil {
		return fmt.Errorf("failed reading key %x: %v", keyID, err)
	}
	return b.mkUpdate(AUM{MessageKind: AUMUpdateKey, Votes: &votes, KeyID: keyID})
}

// SetKeyMeta updates key-value metadata stored against an existing key.
//
// TODO(tom): Provide an API to update specific values rather than the whole
// map.
func (b *UpdateBuilder) SetKeyMeta(keyID tkatype.KeyID, meta map[string]string) error {
	if _, err := b.state.GetKey(keyID); err != nil {
		return fmt.Errorf("failed reading key %x: %v", keyID, err)
	}
	return b.mkUpdate(AUM{MessageKind: AUMUpdateKey, Meta: meta, KeyID: keyID})
}

func (b *UpdateBuilder) generateCheckpoint() error {
	// Compute the checkpoint state.
	state := b.a.state
	for i, update := range b.out {
		var err error
		if state, err = state.applyVerifiedAUM(update); err != nil {
			return fmt.Errorf("applying update %d: %v", i, err)
		}
	}

	// Checkpoints can't specify a parent AUM.
	state.LastAUMHash = nil
	return b.mkUpdate(AUM{MessageKind: AUMCheckpoint, State: &state})
}

// checkpointEvery sets how often a checkpoint AUM should be generated.
const checkpointEvery = 50

// Finalize returns the set of update message to actuate the update.
func (b *UpdateBuilder) Finalize(storage Chonk) ([]AUM, error) {
	var (
		needCheckpoint bool    = true
		cursor         AUMHash = b.a.Head()
	)
	for i := len(b.out); i < checkpointEvery; i++ {
		aum, err := storage.AUM(cursor)
		if err != nil {
			if err == os.ErrNotExist {
				// The available chain is shorter than the interval to checkpoint at.
				needCheckpoint = false
				break
			}
			return nil, fmt.Errorf("reading AUM (%v): %v", cursor, err)
		}

		if aum.MessageKind == AUMCheckpoint {
			needCheckpoint = false
			break
		}

		parent, hasParent := aum.Parent()
		if !hasParent {
			// We've hit the genesis update, so the chain is shorter than the interval to checkpoint at.
			needCheckpoint = false
			break
		}
		cursor = parent
	}

	if needCheckpoint {
		if err := b.generateCheckpoint(); err != nil {
			return nil, fmt.Errorf("generating checkpoint: %v", err)
		}
	}

	// Check no AUMs were applied in the meantime
	if len(b.out) > 0 {
		if parent, _ := b.out[0].Parent(); parent != b.a.Head() {
			return nil, fmt.Errorf("updates no longer apply to head: based on %x but head is %x", parent, b.a.Head())
		}
	}
	return b.out, nil
}

// NewUpdater returns a builder you can use to make changes to
// the tailnet key authority.
//
// The provided signer function, if non-nil, is called with each update
// to compute and apply signatures.
//
// Updates are specified by calling methods on the returned UpdatedBuilder.
// Call Finalize() when you are done to obtain the specific update messages
// which actuate the changes.
func (a *Authority) NewUpdater(signer Signer) *UpdateBuilder {
	return &UpdateBuilder{
		a:      a,
		signer: signer,
		parent: a.Head(),
		state:  a.state,
	}
}

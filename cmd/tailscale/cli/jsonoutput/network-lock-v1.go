// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package jsonoutput

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
)

// PrintNetworkLockJSONV1 prints the stored TKA state as a JSON object to the CLI,
// in a stable "v1" format.
//
// This format includes:
//
//   - the AUM hash as a base32-encoded string
//   - the raw AUM as base64-encoded bytes
//   - the expanded AUM, which prints named fields for consumption by other tools
func PrintNetworkLockJSONV1(out io.Writer, updates []ipnstate.NetworkLockUpdate) error {
	messages := make([]logMessageV1, len(updates))

	for i, update := range updates {
		var aum tka.AUM
		if err := aum.Unserialize(update.Raw); err != nil {
			return fmt.Errorf("decoding: %w", err)
		}

		h := aum.Hash()

		if !bytes.Equal(h[:], update.Hash[:]) {
			return fmt.Errorf("incorrect AUM hash: got %v, want %v", h, update)
		}

		messages[i] = toLogMessageV1(aum, update)
	}

	result := struct {
		ResponseEnvelope
		Messages []logMessageV1
	}{
		ResponseEnvelope: ResponseEnvelope{
			SchemaVersion: "1",
		},
		Messages: messages,
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// toLogMessageV1 converts a [tka.AUM] and [ipnstate.NetworkLockUpdate] to the
// JSON output returned by the CLI.
func toLogMessageV1(aum tka.AUM, update ipnstate.NetworkLockUpdate) logMessageV1 {
	expandedAUM := expandedAUMV1{}
	expandedAUM.MessageKind = aum.MessageKind.String()
	if len(aum.PrevAUMHash) > 0 {
		expandedAUM.PrevAUMHash = aum.PrevAUMHash.String()
	}
	if key := aum.Key; key != nil {
		expandedAUM.Key = toExpandedKeyV1(key)
	}
	if keyID := aum.KeyID; keyID != nil {
		expandedAUM.KeyID = fmt.Sprintf("tlpub:%x", keyID)
	}
	if state := aum.State; state != nil {
		expandedState := expandedStateV1{}
		if h := state.LastAUMHash; h != nil {
			expandedState.LastAUMHash = h.String()
		}
		for _, secret := range state.DisablementSecrets {
			expandedState.DisablementSecrets = append(expandedState.DisablementSecrets, fmt.Sprintf("%x", secret))
		}
		for _, key := range state.Keys {
			expandedState.Keys = append(expandedState.Keys, toExpandedKeyV1(&key))
		}
		expandedState.StateID1 = state.StateID1
		expandedState.StateID2 = state.StateID2
		expandedAUM.State = expandedState
	}
	if votes := aum.Votes; votes != nil {
		expandedAUM.Votes = *votes
	}
	expandedAUM.Meta = aum.Meta
	for _, signature := range aum.Signatures {
		expandedAUM.Signatures = append(expandedAUM.Signatures, expandedSignatureV1{
			KeyID:     fmt.Sprintf("tlpub:%x", signature.KeyID),
			Signature: base64.URLEncoding.EncodeToString(signature.Signature),
		})
	}

	return logMessageV1{
		Hash: aum.Hash().String(),
		AUM:  expandedAUM,
		Raw:  base64.URLEncoding.EncodeToString(update.Raw),
	}
}

// toExpandedKeyV1 converts a [tka.Key] to the JSON output returned
// by the CLI.
func toExpandedKeyV1(key *tka.Key) expandedKeyV1 {
	return expandedKeyV1{
		Kind:   key.Kind.String(),
		Votes:  key.Votes,
		Public: fmt.Sprintf("tlpub:%x", key.Public),
		Meta:   key.Meta,
	}
}

// logMessageV1 is the JSON representation of an AUM as both raw bytes and
// in its expanded form, and the CLI output is a list of these entries.
type logMessageV1 struct {
	// The BLAKE2s digest of the CBOR-encoded AUM.  This is printed as a
	// base32-encoded string, e.g. KCE…XZQ
	Hash string

	// The expanded form of the AUM, which presents the fields in a more
	// accessible format than doing a CBOR decoding.
	AUM expandedAUMV1

	// The raw bytes of the CBOR-encoded AUM, encoded as base64.
	// This is useful for verifying the AUM hash.
	Raw string
}

// expandedAUMV1 is the expanded version of a [tka.AUM], designed so external tools
// can read the AUM without knowing our CBOR definitions.
type expandedAUMV1 struct {
	MessageKind string
	PrevAUMHash string `json:"PrevAUMHash,omitzero"`

	// Key encodes a public key to be added to the key authority.
	// This field is used for AddKey AUMs.
	Key expandedKeyV1 `json:"Key,omitzero"`

	// KeyID references a public key which is part of the key authority.
	// This field is used for RemoveKey and UpdateKey AUMs.
	KeyID string `json:"KeyID,omitzero"`

	// State describes the full state of the key authority.
	// This field is used for Checkpoint AUMs.
	State expandedStateV1 `json:"State,omitzero"`

	// Votes and Meta describe properties of a key in the key authority.
	// These fields are used for UpdateKey AUMs.
	Votes uint              `json:"Votes,omitzero"`
	Meta  map[string]string `json:"Meta,omitzero"`

	// Signatures lists the signatures over this AUM.
	Signatures []expandedSignatureV1 `json:"Signatures,omitzero"`
}

// expandedAUMV1 is the expanded version of a [tka.Key], which describes
// the public components of a key known to network-lock.
type expandedKeyV1 struct {
	Kind string

	// Votes describes the weight applied to signatures using this key.
	Votes uint

	// Public encodes the public key of the key as a hex string.
	Public string

	// Meta describes arbitrary metadata about the key. This could be
	// used to store the name of the key, for instance.
	Meta map[string]string `json:"Meta,omitzero"`
}

// expandedStateV1 is the expanded version of a [tka.State], which describes
// Tailnet Key Authority state at an instant in time.
type expandedStateV1 struct {
	// LastAUMHash is the blake2s digest of the last-applied AUM.
	LastAUMHash string `json:"LastAUMHash,omitzero"`

	// DisablementSecrets are KDF-derived values which can be used
	// to turn off the TKA in the event of a consensus-breaking bug.
	DisablementSecrets []string

	// Keys are the public keys of either:
	//
	//   1. The signing nodes currently trusted by the TKA.
	//   2. Ephemeral keys that were used to generate pre-signed auth keys.
	Keys []expandedKeyV1

	// StateID's are nonce's, generated on enablement and fixed for
	// the lifetime of the Tailnet Key Authority.
	StateID1 uint64
	StateID2 uint64
}

// expandedSignatureV1 is the expanded form of a [tka.Signature], which
// describes a signature over an AUM. This signature can be verified
// using the key referenced by KeyID.
type expandedSignatureV1 struct {
	KeyID     string
	Signature string
}

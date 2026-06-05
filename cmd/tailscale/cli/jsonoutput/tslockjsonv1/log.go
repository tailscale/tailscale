// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package tslockjsonv1

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"tailscale.com/cmd/tailscale/cli/jsonoutput"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
)

// PrintNetworkLockLogJSONV1 prints the stored TKA state as a JSON object to the CLI,
// in a stable "v1" format.
//
// This format includes:
//
//   - the AUM hash as a base32-encoded string
//   - the raw AUM as base64-encoded bytes
//   - the expanded AUM, which prints named fields for consumption by other tools
func PrintNetworkLockLogJSONV1(out io.Writer, updates []ipnstate.NetworkLockUpdate) error {
	messages := make([]LogMessage, len(updates))

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

	result := LogResponse{
		ResponseEnvelope: jsonoutput.ResponseEnvelope{
			SchemaVersion: "1",
		},
		Messages: messages,
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// LogResponse is the full Tailnet Lock log output collected from the local Tailscale daemon.
type LogResponse struct {
	jsonoutput.ResponseEnvelope
	Messages []LogMessage
}

// toLogMessageV1 converts a [tka.AUM] and [ipnstate.NetworkLockUpdate] to the
// JSON output returned by the CLI.
func toLogMessageV1(aum tka.AUM, update ipnstate.NetworkLockUpdate) LogMessage {
	expandedAUM := AUM{}
	expandedAUM.MessageKind = aum.MessageKind.String()
	if len(aum.PrevAUMHash) > 0 {
		expandedAUM.PrevAUMHash = aum.PrevAUMHash.String()
	}
	if key := aum.Key; key != nil {
		expandedAUM.Key = toTKAKeyV1(key)
	}
	if keyID := aum.KeyID; keyID != nil {
		expandedAUM.KeyID = fmt.Sprintf("tlpub:%x", keyID)
	}
	if state := aum.State; state != nil {
		expandedState := TKAState{}
		if h := state.LastAUMHash; h != nil {
			expandedState.LastAUMHash = h.String()
		}
		for _, secret := range state.DisablementValues {
			expandedState.DisablementValues = append(expandedState.DisablementValues, fmt.Sprintf("%x", secret))
		}
		for _, key := range state.Keys {
			expandedState.Keys = append(expandedState.Keys, toTKAKeyV1(&key))
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
		expandedAUM.Signatures = append(expandedAUM.Signatures, Signature{
			KeyID:     fmt.Sprintf("tlpub:%x", signature.KeyID),
			Signature: base64.URLEncoding.EncodeToString(signature.Signature),
		})
	}

	return LogMessage{
		Hash: aum.Hash().String(),
		AUM:  expandedAUM,
		Raw:  base64.URLEncoding.EncodeToString(update.Raw),
	}
}

// LogMessage is the JSON representation of a [tka.AUM] as both raw bytes and
// in its expanded form, and the CLI output is a list of these entries.
type LogMessage struct {
	// The BLAKE2s digest of the CBOR-encoded [tka.AUM].  This is printed as a
	// base32-encoded string, e.g. KCE…XZQ
	Hash string

	// The expanded form of the [tka.AUM], which presents the fields in a more
	// accessible format than doing a CBOR decoding.
	AUM AUM

	// The raw bytes of the CBOR-encoded [tka.AUM], encoded as base64.
	// This is useful for verifying the AUM hash.
	Raw string
}

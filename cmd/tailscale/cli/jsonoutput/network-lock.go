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

// PrintNetworkLockJSON prints the output of `tailscale lock log --json=N`
// to the provided buffer.
//
// If it receives an unrecognised version, it returns an error.
func PrintNetworkLockJSON(out io.Writer, updates []ipnstate.NetworkLockUpdate, jsonVersion int) error {
	if jsonVersion == 1 {
		return printNetworkLockJSONV1(out, updates)
	} else {
		return fmt.Errorf("unrecognised version: %q", jsonVersion)
	}
}

func printNetworkLockJSONV1(out io.Writer, updates []ipnstate.NetworkLockUpdate) error {
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

		messages[i] = logMessageV1{
			Hash: aum.Hash(),
			AUM:  aum,
			Raw:  base64.URLEncoding.EncodeToString(update.Raw),
		}
	}

	result := struct {
		SchemaVersion string
		Messages      []logMessageV1
	}{
		SchemaVersion: "1",
		Messages:      messages,
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// logMessageV1 is the JSON representation of an AUM as both raw bytes and
// in its expanded form, and the CLI output is a list of these entries.
type logMessageV1 struct {
	// The BLAKE2s digest of the CBOR-encoded AUM.
	Hash tka.AUMHash

	// The expanded form of the AUM, which presents the fields in a more
	// accessible format than doing a CBOR decoding.
	AUM tka.AUM

	// The raw bytes of the CBOR-encoded AUM, encoded as base64.
	// This is useful for verifying the AUM hash.
	Raw string
}

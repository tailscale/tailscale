// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package tslockjsonv1

import (
	"encoding/base64"
	"fmt"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
)

// expandedAUMV1 is the expanded version of a [tka.AUM], designed so external tools
// can read the AUM without knowing our CBOR definitions.
type expandedAUMV1 struct {
	MessageKind string
	PrevAUMHash string `json:"PrevAUMHash,omitzero"`

	// Key encodes a public key to be added to the key authority.
	// This field is used for AddKey AUMs.
	Key tkaKeyV1 `json:"Key,omitzero"`

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

// tkaKeyV1 is the expanded version of a [tka.Key], which describes
// the public components of a key known to tailnet-lock.
type tkaKeyV1 struct {
	Kind string `json:"Kind,omitzero"`

	// Votes describes the weight applied to signatures using this key.
	Votes uint

	// Public encodes the public key of the key as a hex string.
	Public string

	// Meta describes arbitrary metadata about the key. This could be
	// used to store the name of the key, for instance.
	Meta map[string]string `json:"Meta,omitzero"`
}

// ipnTKAKeytoTKAKeyV1 converts an [ipnstate.TKAKey] to the JSON output returned
// by the CLI.
func ipnTKAKeytoTKAKeyV1(key *ipnstate.TKAKey) tkaKeyV1 {
	return tkaKeyV1{
		Kind:   key.Kind,
		Votes:  key.Votes,
		Public: key.Key.CLIString(),
		Meta:   key.Metadata,
	}
}

// toTKAKeyV1 converts a [tka.Key] to the JSON output returned
// by the CLI.
func toTKAKeyV1(key *tka.Key) tkaKeyV1 {
	return tkaKeyV1{
		Kind:   key.Kind.String(),
		Votes:  key.Votes,
		Public: fmt.Sprintf("tlpub:%x", key.Public),
		Meta:   key.Meta,
	}
}

// tkaNodeKeySignatureV1 is the JSON representation of a [tka.NodeKeySignature],
// which describes a signature that authorizes a specific node key.
type tkaNodeKeySignatureV1 struct {
	// SigKind identifies the variety of signature.
	SigKind string

	// PublicKey identifies the key.NodePublic which is being authorized.
	// SigCredential signatures do not use this field.
	PublicKey string `json:"PublicKey,omitzero"`

	// KeyID identifies which key in the tailnet key authority should
	// be used to verify this signature. Only set for SigDirect and
	// SigCredential signature kinds.
	KeyID string `json:"KeyID,omitzero"`

	// Signature is the packed (R, S) ed25519 signature over all other
	// fields of the structure.
	Signature string

	// Nested describes a NodeKeySignature which authorizes the node-key
	// used as Pubkey. Only used for SigRotation signatures.
	Nested *tkaNodeKeySignatureV1 `json:"Nested,omitzero"`

	// WrappingPubkey specifies the ed25519 public key which must be used
	// to sign a Signature which embeds this one.
	WrappingPublicKey string `json:"WrappingPublicKey,omitzero"`
}

func toTKANodeKeySignatureV1(sig *tka.NodeKeySignature) *tkaNodeKeySignatureV1 {
	out := tkaNodeKeySignatureV1{
		SigKind: sig.SigKind.String(),
	}
	if len(sig.Pubkey) > 0 {
		out.PublicKey = fmt.Sprintf("tlpub:%x", sig.Pubkey)
	}
	if len(sig.KeyID) > 0 {
		out.KeyID = fmt.Sprintf("tlpub:%x", sig.KeyID)
	}
	out.Signature = base64.URLEncoding.EncodeToString(sig.Signature)
	if sig.Nested != nil {
		out.Nested = toTKANodeKeySignatureV1(sig.Nested)
	}
	if len(sig.WrappingPubkey) > 0 {
		out.WrappingPublicKey = fmt.Sprintf("tlpub:%x", sig.WrappingPubkey)
	}
	return &out
}

// tkaPeerV1 is the JSON representation of an [ipnstate.TKAPeer], which describes
// a peer and its Tailnet Lock details.
type tkaPeerV1 struct {
	// Stable ID, i.e. [tailcfg.StableNodeID]
	ID string

	// DNS name
	DNSName string

	// Tailscale IP(s) assigned to this node
	TailscaleIPs []string

	// The node's public key
	NodeKey string
}

// tkaPeerV1 is the JSON representation of a trusted [ipnstate.TKAPeer], which
// has a node key signature.
type tkaTrustedPeerV1 struct {
	tkaPeerV1

	// The node's key signature
	NodeKeySignature *tkaNodeKeySignatureV1 `json:"NodeKeySignature,omitzero"`
}

func toTKAPeerV1(peer *ipnstate.TKAPeer) tkaPeerV1 {
	out := tkaPeerV1{
		DNSName: peer.Name,
		ID:      string(peer.StableID),
	}
	for _, ip := range peer.TailscaleIPs {
		out.TailscaleIPs = append(out.TailscaleIPs, ip.String())
	}
	out.NodeKey = peer.NodeKey.String()

	return out
}

// expandedSignatureV1 is the expanded form of a [tka.Signature], which
// describes a signature over an AUM. This signature can be verified
// using the key referenced by KeyID.
type expandedSignatureV1 struct {
	KeyID     string
	Signature string
}

// expandedStateV1 is the expanded version of a [tka.State], which describes
// Tailnet Key Authority state at an instant in time.
type expandedStateV1 struct {
	// LastAUMHash is the blake2s digest of the last-applied AUM.
	LastAUMHash string `json:"LastAUMHash,omitzero"`

	// DisablementValues are KDF-derived values used to verify that a caller
	// possesses a valid DisablementSecret. These values are used during the
	// Tailnet Lock deactivation process.
	//
	// These are  safe to share publicly or store in the clear. They cannot be
	// used to derive the original DisablementSecret.
	DisablementValues []string

	// Keys are the public keys of either:
	//
	//   1. The signing nodes currently trusted by the TKA.
	//   2. Ephemeral keys that were used to generate pre-signed auth keys.
	Keys []tkaKeyV1

	// StateID's are nonce's, generated on enablement and fixed for
	// the lifetime of the Tailnet Key Authority.
	StateID1 uint64
	StateID2 uint64
}

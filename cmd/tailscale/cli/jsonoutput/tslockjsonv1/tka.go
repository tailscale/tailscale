// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package tslockjsonv1

// AUM is the expanded version of a [tka.AUM], designed so external tools
// can read the AUM without knowing our CBOR definitions.
type AUM struct {
	MessageKind string
	PrevAUMHash string `json:",omitzero"`

	// Key encodes a public key to be added to the key authority.
	// This field is used for AddKey AUMs.
	Key Key `json:",omitzero"`

	// KeyID references a public key which is part of the key authority.
	// This field is used for RemoveKey and UpdateKey AUMs.
	KeyID string `json:",omitzero"`

	// State describes the full state of the key authority.
	// This field is used for Checkpoint AUMs.
	State TKAState `json:",omitzero"`

	// Votes and Meta describe properties of a key in the key authority.
	// These fields are used for UpdateKey AUMs.
	Votes uint              `json:",omitzero"`
	Meta  map[string]string `json:",omitzero"`

	// Signatures lists the signatures over this AUM.
	Signatures []Signature `json:",omitzero"`
}

// Key is the expanded version of a [tka.Key], which describes
// the public components of a key known to tailnet-lock.
type Key struct {
	Kind string `json:",omitzero"`

	// Votes describes the weight applied to signatures using this key.
	Votes uint

	// Public encodes the public key of the key as a hex string.
	Public string

	// Meta describes arbitrary metadata about the key. This could be
	// used to store the name of the key, for instance.
	Meta map[string]string `json:",omitzero"`
}

// NodeKeySignature is the JSON representation of a [tka.NodeKeySignature],
// which describes a signature that authorizes a specific node key.
type NodeKeySignature struct {
	// SigKind identifies the variety of signature.
	SigKind string

	// PublicKey identifies the key.NodePublic which is being authorized.
	// SigCredential signatures do not use this field.
	PublicKey string `json:",omitzero"`

	// KeyID identifies which key in the tailnet key authority should
	// be used to verify this signature. Only set for SigDirect and
	// SigCredential signature kinds.
	KeyID string `json:",omitzero"`

	// Signature is the packed (R, S) ed25519 signature over all other
	// fields of the structure.
	Signature string

	// Nested describes a NodeKeySignature which authorizes the node-key
	// used as Pubkey. Only used for SigRotation signatures.
	Nested *NodeKeySignature `json:",omitzero"`

	// WrappingPubkey specifies the ed25519 public key which must be used
	// to sign a Signature which embeds this one.
	WrappingPublicKey string `json:",omitzero"`
}

// Peer is the JSON representation of an [ipnstate.TKAPeer], which describes
// a peer and its Tailnet Lock details.
type Peer struct {
	// Stable ID, i.e. [tailscale.com/tailcfg.StableNodeID]
	ID string

	// DNS name
	DNSName string

	// Tailscale IP(s) assigned to this node
	TailscaleIPs []string

	// The node's public key
	NodeKey string
}

// TrustedPeer is the JSON representation of a trusted [ipnstate.TKAPeer], which
// has a node key signature in addition to [Peer].
type TrustedPeer struct {
	// Stable ID, i.e. [tailscale.com/tailcfg.StableNodeID]
	ID string

	// DNS name
	DNSName string

	// Tailscale IP(s) assigned to this node
	TailscaleIPs []string

	// The node's public key
	NodeKey string

	// The node's key signature
	NodeKeySignature *NodeKeySignature `json:",omitzero"`
}

// Signature is the expanded form of a [tka.Signature], which
// describes a signature over an AUM. This signature can be verified
// using the key referenced by KeyID.
type Signature struct {
	KeyID     string
	Signature string
}

// TKAState is the expanded version of a [tka.TKAState], which describes
// Tailnet Key Authority state at an instant in time.
type TKAState struct {
	// LastAUMHash is the blake2s digest of the last-applied AUM.
	LastAUMHash string `json:",omitzero"`

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
	Keys []Key

	// StateID's are nonce's, generated on enablement and fixed for
	// the lifetime of the Tailnet Key Authority.
	StateID1 uint64
	StateID2 uint64
}

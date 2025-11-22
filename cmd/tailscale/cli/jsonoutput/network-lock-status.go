// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package jsonoutput

import (
	"encoding/base64"
	jsonv1 "encoding/json"
	"fmt"
	"io"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
)

// PrintNetworkLockStatusJSONV1 prints the current Tailnet Lock status
// as a JSON object to the CLI, in a stable "v1" format.
func PrintNetworkLockStatusJSONV1(out io.Writer, status *ipnstate.NetworkLockStatus) error {
	responseEnvelope := ResponseEnvelope{
		SchemaVersion: "1",
	}

	var result any
	if status.Enabled {
		result = struct {
			ResponseEnvelope
			tailnetLockStatusV1
		}{
			ResponseEnvelope:    responseEnvelope,
			tailnetLockStatusV1: toTailnetLockStatusV1(status),
		}
	} else {
		result = struct {
			ResponseEnvelope
			Enabled bool
		}{
			ResponseEnvelope: responseEnvelope,
			Enabled:          false,
		}
	}

	enc := jsonv1.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// toTailnetLockStatusV1 converts a status to the JSON output expected by the CLI.
func toTailnetLockStatusV1(status *ipnstate.NetworkLockStatus) tailnetLockStatusV1 {
	out := tailnetLockStatusV1{
		Enabled: status.Enabled,
	}

	if status.Head != nil {
		out.Head = status.Head.String()
	}
	if !status.PublicKey.IsZero() {
		publicKey := status.PublicKey.CLIString()
		out.PublicKey = &publicKey
	}
	if nk := status.NodeKey; nk != nil {
		nodeKey := nk.String()
		out.NodeKey = &nodeKey
	}
	out.NodeKeySigned = status.NodeKeySigned
	if sig := status.NodeKeySignature; sig != nil {
		out.NodeKeySignature = toTKANodeKeySignatureV1(sig)
	}
	for _, key := range status.TrustedKeys {
		out.TrustedKeys = append(out.TrustedKeys, toTKAKeyV1(&key))
	}
	for _, vp := range status.VisiblePeers {
		out.VisiblePeers = append(out.VisiblePeers, tkaTrustedPeerV1{
			tkaPeerV1:        toTKAPeerV1(vp),
			NodeKeySignature: toTKANodeKeySignatureV1(&vp.NodeKeySignature),
		})
	}
	for _, fp := range status.FilteredPeers {
		out.FilteredPeers = append(out.FilteredPeers, toTKAPeerV1(fp))
	}
	out.StateID = status.StateID

	return out
}

// tailnetLockStatusV1 is the JSON representation of the Tailnet Lock status.
type tailnetLockStatusV1 struct {
	// Enabled is true if Tailnet Lock is enabled.
	Enabled bool

	// Head describes the AUM hash of the leaf AUM. Head is nil
	// if network lock is not enabled.
	Head string `json:"Head,omitzero"`

	// PublicKey describes the node's network-lock public key.
	// It may be nil if the node has not logged in.
	PublicKey *string

	// NodeKey describes the node's current node-key. This field is not
	// populated if the node is not operating (i.e. waiting for a login).
	NodeKey *string

	// NodeKeySigned is true if our node is authorized by Tailnet Lock.
	NodeKeySigned bool

	// NodeKeySignature is the current signature of this node's key.
	NodeKeySignature *tkaNodeKeySignatureV1

	// TrustedKeys describes the keys currently trusted to make changes
	// to network-lock.
	TrustedKeys []tkaKeyV1

	// VisiblePeers describes peers which are visible in the netmap that
	// have valid Tailnet Lock signatures signatures.
	VisiblePeers []tkaTrustedPeerV1

	// FilteredPeers describes peers which were removed from the netmap
	// (i.e. no connectivity) because they failed Tailnet Lock
	// checks.
	FilteredPeers []tkaPeerV1

	// StateID is a nonce associated with the Tailnet Lock authority,
	// generated upon enablement. This field is empty if Tailnet Lock
	// is disabled.
	StateID uint64 `json:"State,omitzero"`
}

// tkaPeerV1 is the JSON representation of an [ipnstate.TKAPeer], which describes
// a peer and its Tailnet Lock details.
type tkaPeerV1 struct {
	// DNS name
	Name string

	// Node ID, i.e. [tailcfg.NodeID]
	ID string

	// Stable ID, i.e. [tailcfg.StableNodeID]
	StableID string

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
		Name:     peer.Name,
		ID:       peer.ID.String(),
		StableID: string(peer.StableID),
	}
	for _, ip := range peer.TailscaleIPs {
		out.TailscaleIPs = append(out.TailscaleIPs, ip.String())
	}
	out.NodeKey = peer.NodeKey.String()

	return out
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
		out.WrappingPublicKey = fmt.Sprintf("tlpub:%x", out.WrappingPublicKey)
	}
	return &out
}

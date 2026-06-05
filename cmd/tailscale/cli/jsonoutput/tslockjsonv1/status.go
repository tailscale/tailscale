// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package tslockjsonv1

import "tailscale.com/cmd/tailscale/cli/jsonoutput"

// StatusResponse is the full Tailnet Lock Status output collected from the local Tailscale daemon.
type StatusResponse struct {
	jsonoutput.ResponseEnvelope

	// Enabled is true if Tailnet Lock is enabled.
	Enabled bool

	// PublicKey describes the node's tailnet-lock public key.
	PublicKey string `json:",omitzero"`

	// NodeKey describes the node's current node-key. This field is not
	// populated if the node is not operating (i.e. waiting for a login).
	NodeKey string `json:",omitzero"`

	//////////////////////////////////////////////////////////////////
	// The following fields are only present when Tailnet Lock is enabled.

	// Head describes the AUM hash of the leaf AUM.
	Head string `json:",omitzero"`

	// NodeKeySigned is true if our node is authorized by Tailnet Lock.
	NodeKeySigned *bool `json:",omitzero"`

	// NodeKeySignature is the current signature of this node's key.
	NodeKeySignature *NodeKeySignature `json:",omitzero"`

	// TrustedKeys describes the keys currently trusted to make changes
	// to tailnet-lock.
	TrustedKeys []Key `json:",omitzero"`

	// VisiblePeers describes peers which are visible in the netmap that
	// have valid Tailnet Lock signatures signatures.
	VisiblePeers []TrustedPeer `json:",omitzero"`

	// FilteredPeers describes peers which were removed from the netmap
	// (i.e. no connectivity) because they failed Tailnet Lock
	// checks.
	FilteredPeers []Peer `json:",omitzero"`

	// StateID is a nonce associated with the Tailnet Lock authority,
	// generated upon enablement. This field is empty if Tailnet Lock
	// is disabled.
	StateID uint64 `json:"State,omitzero"`
}

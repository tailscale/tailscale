// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package tslockjsonv1

import (
	jsonv1 "encoding/json"
	"io"

	"tailscale.com/cmd/tailscale/cli/jsonoutput"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
)

// PrintNetworkLockStatusJSONV1 prints the current Tailnet Lock status
// as a JSON object to the CLI, in a stable "v1" format.
func PrintNetworkLockStatusJSONV1(out io.Writer, status *ipnstate.NetworkLockStatus) error {
	responseEnvelope := jsonoutput.ResponseEnvelope{
		SchemaVersion: "1",
	}

	var result StatusResponse
	if status.Enabled {
		result = toTailnetLockEnabledStatusV1(status)
		result.ResponseEnvelope = responseEnvelope
	} else {
		result = toTailnetLockDisabledStatusV1(status)
		result.ResponseEnvelope = responseEnvelope
	}

	enc := jsonv1.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func toTailnetLockDisabledStatusV1(status *ipnstate.NetworkLockStatus) StatusResponse {
	out := StatusResponse{
		Enabled: status.Enabled,
	}
	if !status.PublicKey.IsZero() {
		out.PublicKey = status.PublicKey.CLIString()
	}
	if nk := status.NodeKey; nk != nil {
		out.NodeKey = nk.String()
	}
	return out
}

func toTailnetLockEnabledStatusV1(status *ipnstate.NetworkLockStatus) StatusResponse {
	out := StatusResponse{
		Enabled: status.Enabled,
	}

	if status.Head != nil {
		var head tka.AUMHash
		h := status.Head
		copy(head[:], h[:])
		out.Head = head.String()
	}
	if !status.PublicKey.IsZero() {
		out.PublicKey = status.PublicKey.CLIString()
	}
	if nk := status.NodeKey; nk != nil {
		out.NodeKey = nk.String()
	}
	out.NodeKeySigned = &status.NodeKeySigned
	if sig := status.NodeKeySignature; sig != nil {
		out.NodeKeySignature = toTKANodeKeySignatureV1(sig)
	}
	out.TrustedKeys = []Key{} // never omit this field when enabled
	for _, key := range status.TrustedKeys {
		out.TrustedKeys = append(out.TrustedKeys, ipnTKAKeytoTKAKeyV1(&key))
	}
	out.VisiblePeers = []TrustedPeer{} // never omit this field when enabled
	for _, vp := range status.VisiblePeers {
		out.VisiblePeers = append(out.VisiblePeers, toTrustedTKAPeerV1(vp))
	}
	out.FilteredPeers = []Peer{} // never omit this field when enabled
	for _, fp := range status.FilteredPeers {
		out.FilteredPeers = append(out.FilteredPeers, toTKAPeerV1(fp))
	}
	out.StateID = status.StateID

	return out
}

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

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

	var result any
	if status.Enabled {
		result = struct {
			jsonoutput.ResponseEnvelope
			tailnetLockEnabledStatusV1
		}{
			ResponseEnvelope:           responseEnvelope,
			tailnetLockEnabledStatusV1: toTailnetLockEnabledStatusV1(status),
		}
	} else {
		result = struct {
			jsonoutput.ResponseEnvelope
			tailnetLockDisabledStatusV1
		}{
			ResponseEnvelope:            responseEnvelope,
			tailnetLockDisabledStatusV1: toTailnetLockDisabledStatusV1(status),
		}
	}

	enc := jsonv1.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func toTailnetLockDisabledStatusV1(status *ipnstate.NetworkLockStatus) tailnetLockDisabledStatusV1 {
	out := tailnetLockDisabledStatusV1{
		tailnetLockStatusV1Base: tailnetLockStatusV1Base{
			Enabled: status.Enabled,
		},
	}
	if !status.PublicKey.IsZero() {
		out.PublicKey = status.PublicKey.CLIString()
	}
	if nk := status.NodeKey; nk != nil {
		out.NodeKey = nk.String()
	}
	return out
}

func toTailnetLockEnabledStatusV1(status *ipnstate.NetworkLockStatus) tailnetLockEnabledStatusV1 {
	out := tailnetLockEnabledStatusV1{
		tailnetLockStatusV1Base: tailnetLockStatusV1Base{
			Enabled: status.Enabled,
		},
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
	out.NodeKeySigned = status.NodeKeySigned
	if sig := status.NodeKeySignature; sig != nil {
		out.NodeKeySignature = toTKANodeKeySignatureV1(sig)
	}
	for _, key := range status.TrustedKeys {
		out.TrustedKeys = append(out.TrustedKeys, ipnTKAKeytoTKAKeyV1(&key))
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

type tailnetLockStatusV1Base struct {
	// Enabled is true if Tailnet Lock is enabled.
	Enabled bool

	// PublicKey describes the node's tailnet-lock public key.
	PublicKey string `json:"PublicKey,omitzero"`

	// NodeKey describes the node's current node-key. This field is not
	// populated if the node is not operating (i.e. waiting for a login).
	NodeKey string `json:"NodeKey,omitzero"`
}

// tailnetLockDisabledStatusV1 is the JSON representation of the Tailnet Lock status
// when Tailnet Lock is disabled.
type tailnetLockDisabledStatusV1 struct {
	tailnetLockStatusV1Base
}

// tailnetLockEnabledStatusV1 is the JSON representation of the Tailnet Lock status.
type tailnetLockEnabledStatusV1 struct {
	tailnetLockStatusV1Base

	// Head describes the AUM hash of the leaf AUM.
	Head string `json:"Head,omitzero"`

	// NodeKeySigned is true if our node is authorized by Tailnet Lock.
	NodeKeySigned bool

	// NodeKeySignature is the current signature of this node's key.
	NodeKeySignature *tkaNodeKeySignatureV1

	// TrustedKeys describes the keys currently trusted to make changes
	// to tailnet-lock.
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

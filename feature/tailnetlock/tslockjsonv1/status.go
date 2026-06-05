// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tslockjsonv1

import (
	"tailscale.com/cmd/tailscale/cli/jsonoutput"
	"tailscale.com/cmd/tailscale/cli/jsonoutput/tslockjsonv1"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
)

// StatusResponse returns the current Tailnet Lock status as a JSON object to the CLI,
// in a stable "v1" format.
func StatusResponse(status *ipnstate.NetworkLockStatus) tslockjsonv1.StatusResponse {
	out := tslockjsonv1.StatusResponse{
		ResponseEnvelope: jsonoutput.ResponseEnvelope{
			SchemaVersion: "1",
		},
		Enabled: status.Enabled,
	}
	if !status.PublicKey.IsZero() {
		out.PublicKey = status.PublicKey.CLIString()
	}
	if nk := status.NodeKey; nk != nil {
		out.NodeKey = nk.String()
	}
	if !status.Enabled {
		return out // Tailnet Lock is disabled, omit the following fields
	}

	if status.Head != nil {
		var head tka.AUMHash
		h := status.Head
		copy(head[:], h[:])
		out.Head = head.String()
	}
	out.NodeKeySigned = &status.NodeKeySigned
	if sig := status.NodeKeySignature; sig != nil {
		out.NodeKeySignature = nodeKeySignature(sig)
	}
	out.TrustedKeys = []tslockjsonv1.Key{} // never omit this field when enabled
	for _, key := range status.TrustedKeys {
		out.TrustedKeys = append(out.TrustedKeys, ipnTKAKey(&key))
	}
	out.VisiblePeers = []tslockjsonv1.TrustedPeer{} // never omit this field when enabled
	for _, vp := range status.VisiblePeers {
		out.VisiblePeers = append(out.VisiblePeers, trustedPeer(vp))
	}
	out.FilteredPeers = []tslockjsonv1.Peer{} // never omit this field when enabled
	for _, fp := range status.FilteredPeers {
		out.FilteredPeers = append(out.FilteredPeers, peer(fp))
	}
	out.StateID = status.StateID
	return out
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package tslockjsonv1

import "tailscale.com/cmd/tailscale/cli/jsonoutput"

// LogResponse is the full Tailnet Lock log output collected from the local Tailscale daemon.
type LogResponse struct {
	jsonoutput.ResponseEnvelope
	Messages []LogMessage
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

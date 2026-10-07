// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package taildroptype holds Taildrop types shared by the feature, notifications,
// and the LocalAPI client.
package taildroptype

import (
	"time"

	"tailscale.com/tailcfg"
)

// ConsentRequest is an inbound Taildrop file awaiting the device owner's
// approval. Each file has its own request and consent token.
type ConsentRequest struct {
	// RequestID identifies this request. It is passed back to the LocalAPI
	// to approve or deny, and is not reused.
	RequestID string

	// PeerID is the stable node ID of the sending node.
	PeerID tailcfg.StableNodeID

	// PeerName is the sending node's display name, for showing to the user.
	PeerName string

	// Files contains the single file the peer wants to send.
	Files []ConsentFile

	// TotalSize is the sum of the sizes of Files, in bytes.
	TotalSize int64

	// Requested is when consent for this file was requested.
	Requested time.Time

	// Expires is when this request stops being actionable. Responding after
	// this point has no effect and the sender must ask again.
	Expires time.Time
}

// ConsentFile is a single file within a [ConsentRequest].
type ConsentFile struct {
	Name string // the filename as it will be written to disk i.e. "image.jpg"
	Size int64  // declared size in bytes
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tsrecorder

import "tailscale.com/tailcfg"

// CastHeader is the asciicast header to be sent to the recorder at the start of
// the recording of a session.
// https://docs.asciinema.org/manual/asciicast/v2/#header
type CastHeader struct {
	// Version is the asciinema file format version.
	Version int `json:"version"`

	// Width is the terminal width in characters.
	Width int `json:"width"`

	// Height is the terminal height in characters.
	Height int `json:"height"`

	// Timestamp is the unix timestamp of when the recording started.
	Timestamp int64 `json:"timestamp"`

	// Tailscale-specific fields: SrcNode is the full MagicDNS name of the
	// tailnet node originating the connection, without the trailing dot.
	SrcNode string `json:"srcNode"`

	// SrcNodeID is the node ID of the tailnet node originating the connection.
	SrcNodeID tailcfg.StableNodeID `json:"srcNodeID"`

	// SrcNodeTags is the list of tags on the node originating the connection (if any).
	SrcNodeTags []string `json:"srcNodeTags,omitempty"`

	// SrcNodeUserID is the user ID of the node originating the connection (if not tagged).
	SrcNodeUserID tailcfg.UserID `json:"srcNodeUserID,omitempty"` // if not tagged

	// SrcNodeUser is the LoginName of the node originating the connection (if not tagged).
	SrcNodeUser string `json:"srcNodeUser,omitempty"`

	Command string

	// Kubernetes-specific fields:
	Kubernetes *Kubernetes `json:"kubernetes,omitempty"`
}

// Kubernetes contains 'kubectl exec' session specific information for
// tsrecorder.
type Kubernetes struct {
	PodName   string
	Namespace string
	Container string
}

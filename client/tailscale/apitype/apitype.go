// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package apitype contains types for the Tailscale local API and control plane API.
package apitype

import "tailscale.com/tailcfg"

// WhoIsResponse is the JSON type returned by tailscaled debug server's /whois?ip=$IP handler.
type WhoIsResponse struct {
	Node        *tailcfg.Node
	UserProfile *tailcfg.UserProfile

	// Caps are extra capabilities that the remote Node has to this node.
	Caps []string `json:",omitempty"`
}

// FileTarget is a node to which files can be sent, and the PeerAPI
// URL base to do so via.
type FileTarget struct {
	Node *tailcfg.Node

	// PeerAPI is the http://ip:port URL base of the node's peer API,
	// without any path (not even a single slash).
	PeerAPIURL string
}

type WaitingFile struct {
	Name string
	Size int64
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package peercap defines the capabilities that can be granted to peer nodes.
package peercap

// Cap represents a capability granted to a peer by a [tailscale.com/tailcfg.FilterRule]
// when the peer communicates with the node that has this rule.
// Its meaning is application-defined.
//
// It must be a URL like "https://tailscale.com/cap/file-send"
// or "tailscale.com/cap/webui".
type Cap string

const (
	// FileSharingTarget grants the current node the ability to send
	// files to the peer which has this capability.
	FileSharingTarget Cap = "https://tailscale.com/cap/file-sharing-target"
	// FileSharingSend grants the ability to receive files from a
	// node that's owned by a different user.
	FileSharingSend Cap = "https://tailscale.com/cap/file-send"
	// DebugPeer grants the ability for a peer to read this node's
	// goroutines, metrics, magicsock internal state, etc.
	DebugPeer Cap = "https://tailscale.com/cap/debug-peer"
	// WakeOnLAN grants the ability to send a Wake-On-LAN packet.
	WakeOnLAN Cap = "https://tailscale.com/cap/wake-on-lan"
	// Ingress grants the ability for a peer to send ingress traffic.
	Ingress Cap = "https://tailscale.com/cap/ingress"
	// WebUI grants the ability for a peer to edit features from the
	// device Web UI.
	WebUI Cap = "tailscale.com/cap/webui"
	// Taildrive grants the ability for a peer to access Taildrive
	// shares.
	Taildrive Cap = "tailscale.com/cap/drive"
	// TaildriveSharer indicates that a peer has the ability to
	// share folders with us.
	TaildriveSharer Cap = "tailscale.com/cap/drive-sharer"

	// Kubernetes grants a peer Kubernetes-specific
	// capabilities, such as the ability to impersonate specific Tailscale
	// user groups as Kubernetes user groups. This capability is read by
	// peers that are Tailscale Kubernetes operator instances.
	Kubernetes Cap = "tailscale.com/cap/kubernetes"

	// Relay grants the ability for a peer to allocate relay
	// endpoints.
	Relay Cap = "tailscale.com/cap/relay"
	// RelayTarget grants the current node the ability to allocate
	// relay endpoints to the peer which has this capability.
	RelayTarget Cap = "tailscale.com/cap/relay-target"

	// TsIDP grants a peer tsidp-specific
	// capabilities, such as the ability to add user groups to the OIDC
	// claim
	TsIDP Cap = "tailscale.com/cap/tsidp"
)

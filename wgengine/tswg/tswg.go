// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tswg configures tswg, the Tailscale fork of the Linux kernel
// WireGuard module, over its "tswg" generic netlink family.
//
// The tswg uapi is attribute-compatible with upstream WireGuard's; see
// https://github.com/tailscale/tailscale/issues/426.
package tswg

import (
	"net/netip"
	"time"

	"tailscale.com/types/key"
)

// Config is a change to a tswg device's configuration.
// Zero-valued optional fields leave the corresponding setting unchanged.
type Config struct {
	PrivateKey   *key.NodePrivate // nil means unchanged
	ListenPort   *uint16          // nil means unchanged; 0 means random
	ReplacePeers bool             // remove all peers not in Peers
	Peers        []PeerConfig
}

// PeerConfig is a change to one peer of a tswg device.
type PeerConfig struct {
	PublicKey  key.NodePublic
	Remove     bool // remove the peer
	UpdateOnly bool // only update an existing peer; don't create one

	// Endpoint, if valid, sets the peer's endpoint.
	Endpoint netip.AddrPort

	// PersistentKeepalive, if non-nil, sets the persistent keepalive
	// interval. Zero disables it.
	PersistentKeepalive *time.Duration

	// ReplaceAllowedIPs, if true, replaces the peer's allowed IPs with
	// AllowedIPs rather than adding to them.
	ReplaceAllowedIPs bool
	AllowedIPs        []netip.Prefix
}

// Device is the current state of a tswg device.
type Device struct {
	Name         string
	Index        int
	PrivateKey   key.NodePrivate
	PublicKey    key.NodePublic
	ListenPort   uint16
	FirewallMark uint32
	Peers        []Peer
}

// Peer is the current state of one peer of a tswg device.
type Peer struct {
	PublicKey           key.NodePublic
	Endpoint            netip.AddrPort
	PersistentKeepalive time.Duration
	LastHandshake       time.Time
	RxBytes             uint64
	TxBytes             uint64
	AllowedIPs          []netip.Prefix
	ProtocolVersion     int
}

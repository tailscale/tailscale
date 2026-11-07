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
	FirewallMark *uint32          // nil means unchanged; 0 means none
	ReplacePeers bool             // remove all peers not in Peers
	Peers        []PeerConfig

	// SocketFD4 and SocketFD6, if non-nil, are file descriptors, in this
	// process, of bound UDP sockets (IPv4, and IPV6_V6ONLY IPv6) for the
	// device to share with the caller instead of creating its own. The
	// device consumes the WireGuard messages arriving on them and leaves
	// all other datagrams for the caller to read; the caller can send its
	// own datagrams on them too. The device drops a socket when the caller
	// closes it. A value of -1 detaches the current socket, and the device
	// goes back to creating its own.
	SocketFD4, SocketFD6 *int
}

// PeerConfig is a change to one peer of a tswg device.
type PeerConfig struct {
	PublicKey  key.NodePublic
	Remove     bool // remove the peer
	UpdateOnly bool // only update an existing peer; don't create one

	// Endpoint, if valid, sets the peer's endpoint.
	Endpoint netip.AddrPort

	// PresharedKey, if non-nil, sets the peer's preshared key. All zeros
	// removes it.
	PresharedKey *[32]byte

	// PersistentKeepalive, if non-nil, sets the persistent keepalive
	// interval. Zero disables it.
	PersistentKeepalive *time.Duration

	// ReplaceAllowedIPs, if true, replaces the peer's allowed IPs with
	// AllowedIPs rather than adding to them.
	ReplaceAllowedIPs bool
	AllowedIPs        []netip.Prefix

	// NoRoam, if non-nil, sets whether the kernel is prevented from
	// updating the peer's endpoint from incoming packets once it has one.
	// tailscaled sets it, since disco picks the path: otherwise a packet
	// arriving via DERP would steal the endpoint from a good direct path.
	// The flag is applied before Endpoint, so setting both is one step.
	NoRoam *bool
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

	// UserSocket4 and UserSocket6 report whether the device is using a
	// caller-supplied socket (see Config.SocketFD4) for that family.
	UserSocket4, UserSocket6 bool
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
	NoRoam              bool // see PeerConfig.NoRoam
}

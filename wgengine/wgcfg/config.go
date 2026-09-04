// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wgcfg has types and a parser for representing WireGuard config.
package wgcfg

import (
	"net/netip"
	"slices"

	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/types/key"
)

//go:generate go run tailscale.com/cmd/cloner -type=Config

// Config is a WireGuard configuration.
// It only supports the set of things Tailscale uses.
//
// Peers are not part of the config: wireguard-go learns the peer set
// and each peer's configuration from the live per-peer config source
// installed via [tailscale.com/wgengine.Engine.SetPeerConfigFunc].
type Config struct {
	PrivateKey key.NodePrivate
	Addresses  []netip.Prefix
}

// PeerConfig is the WireGuard configuration for one peer.
type PeerConfig struct {
	// AllowedIPs is the set of prefixes the peer may originate traffic from.
	AllowedIPs []netip.Prefix

	// PresharedKey is the optional WireGuard pre-shared key. The zero value
	// disables the pre-shared-key layer.
	PresharedKey device.NoisePresharedKey
}

func (c *Config) Equal(o *Config) bool {
	if c == nil || o == nil {
		return c == o
	}
	return c.PrivateKey.Equal(o.PrivateKey) &&
		slices.Equal(c.Addresses, o.Addresses)
}

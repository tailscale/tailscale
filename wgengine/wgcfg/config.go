// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wgcfg has types and a parser for representing WireGuard config.
package wgcfg

import (
	"net/netip"

	"tailscale.com/logtail"
	"tailscale.com/types/key"
)

//go:generate go run tailscale.com/cmd/cloner -type=Config,Peer

// Config is a WireGuard configuration.
// It only supports the set of things Tailscale uses.
type Config struct {
	Name       string
	PrivateKey key.NodePrivate
	Addresses  []netip.Prefix
	MTU        uint16
	DNS        []netip.Addr
	Peers      []Peer

	// NetworkLogging enables network logging.
	// It is disabled if either ID is the zero value.
	NetworkLogging struct {
		NodeID   logtail.PrivateID
		DomainID logtail.PrivateID
	}
}

type Peer struct {
	PublicKey           key.NodePublic
	DiscoKey            key.DiscoPublic // present only so we can handle restarts within wgengine, not passed to WireGuard
	AllowedIPs          []netip.Prefix
	PersistentKeepalive uint16
	// wireguard-go's endpoint for this peer. It should always equal Peer.PublicKey.
	// We represent it explicitly so that we can detect if they diverge and recover.
	// There is no need to set WGEndpoint explicitly when constructing a Peer by hand.
	// It is only populated when reading Peers from wireguard-go.
	WGEndpoint key.NodePublic
}

// PeerWithKey returns the Peer with key k and reports whether it was found.
func (config Config) PeerWithKey(k key.NodePublic) (Peer, bool) {
	for _, p := range config.Peers {
		if p.PublicKey == k {
			return p, true
		}
	}
	return Peer{}, false
}

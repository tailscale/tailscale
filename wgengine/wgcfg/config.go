// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wgcfg has types and a parser for representing WireGuard config.
package wgcfg

import (
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
)

//go:generate go run tailscale.com/cmd/cloner -type=Config,Peer,Endpoints -output=clone.go

// Config is a WireGuard configuration.
// It only supports the set of things Tailscale uses.
type Config struct {
	Name       string
	PrivateKey wgkey.Private
	Addresses  []netaddr.IPPrefix
	MTU        uint16
	DNS        []netaddr.IP
	Peers      []Peer
}

type Peer struct {
	PublicKey           wgkey.Key
	AllowedIPs          []netaddr.IPPrefix
	Endpoints           Endpoints
	PersistentKeepalive uint16
}

// Endpoints represents the routes to reach a remote node.
// It is serialized and provided to wireguard-go as a conn.Endpoint.
//
// TODO: change name, it's now just a pair of keys representing a peer.
type Endpoints struct {
	// PublicKey is the public key for the remote node.
	PublicKey wgkey.Key `json:"pk"`
	// DiscoKey is the disco key associated with the remote node.
	DiscoKey tailcfg.DiscoKey `json:"dk,omitempty"`
}

// PeerWithKey returns the Peer with key k and reports whether it was found.
func (config Config) PeerWithKey(k wgkey.Key) (Peer, bool) {
	for _, p := range config.Peers {
		if p.PublicKey == k {
			return p, true
		}
	}
	return Peer{}, false
}

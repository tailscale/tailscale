// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wgcfg has types and a parser for representing WireGuard config.
package wgcfg

import (
	"inet.af/netaddr"
	"tailscale.com/types/wgkey"
)

//go:generate go run tailscale.com/cmd/cloner -type=Config,Peer -output=clone.go

// EndpointDiscoSuffix is appended to the hex representation of a peer's discovery key
// and is then the sole wireguard endpoint for peers with a non-zero discovery key.
// This form is then recognize by magicsock's CreateEndpoint.
const EndpointDiscoSuffix = ".disco.tailscale:12345"

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
	Endpoints           string // comma-separated host/port pairs: "1.2.3.4:56,[::]:80"
	PersistentKeepalive uint16
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

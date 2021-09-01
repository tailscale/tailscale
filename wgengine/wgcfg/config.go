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

//go:generate go run tailscale.com/cmd/cloner -type=Config,Peer -output=clone.go

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
	DiscoKey            tailcfg.DiscoKey // present only so we can handle restarts within wgengine, not passed to WireGuard
	AllowedIPs          []netaddr.IPPrefix
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

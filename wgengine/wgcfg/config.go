// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wgcfg has types and a parser for representing WireGuard config.
package wgcfg

import (
	"encoding/json"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
)

//go:generate go run tailscale.com/cmd/cloner -type=Config,Peer,Endpoints,IPPortSet -output=clone.go

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
type Endpoints struct {
	// PublicKey is the public key for the remote node.
	PublicKey wgkey.Key `json:"pk"`
	// DiscoKey is the disco key associated with the remote node.
	DiscoKey tailcfg.DiscoKey `json:"dk,omitempty"`
	// IPPorts is a set of possible ip+ports the remote node can be reached at.
	// This is used only for legacy connections to pre-disco (pre-0.100) peers.
	IPPorts IPPortSet `json:"ipp,omitempty"`
}

func (e Endpoints) Equal(f Endpoints) bool {
	if e.PublicKey != f.PublicKey {
		return false
	}
	if e.DiscoKey != f.DiscoKey {
		return false
	}
	return e.IPPorts.EqualUnordered(f.IPPorts)
}

// IPPortSet is an immutable slice of netaddr.IPPorts.
type IPPortSet struct {
	ipp []netaddr.IPPort
}

// NewIPPortSet returns an IPPortSet containing the ports in ipp.
func NewIPPortSet(ipps ...netaddr.IPPort) IPPortSet {
	return IPPortSet{ipp: append(ipps[:0:0], ipps...)}
}

// String returns a comma-separated list of all IPPorts in s.
func (s IPPortSet) String() string {
	buf := new(strings.Builder)
	for i, ipp := range s.ipp {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(ipp.String())
	}
	return buf.String()
}

// IPPorts returns a slice of netaddr.IPPorts containing the IPPorts in s.
func (s IPPortSet) IPPorts() []netaddr.IPPort {
	return append(s.ipp[:0:0], s.ipp...)
}

// EqualUnordered reports whether s and t contain the same IPPorts, regardless of order.
func (s IPPortSet) EqualUnordered(t IPPortSet) bool {
	if len(s.ipp) != len(t.ipp) {
		return false
	}
	// Check whether the endpoints are the same, regardless of order.
	ipps := make(map[netaddr.IPPort]int, len(s.ipp))
	for _, ipp := range s.ipp {
		ipps[ipp]++
	}
	for _, ipp := range t.ipp {
		ipps[ipp]--
	}
	for _, n := range ipps {
		if n != 0 {
			return false
		}
	}
	return true
}

// MarshalJSON marshals s into JSON.
// It is necessary so that IPPortSet's fields can be unexported, to guarantee immutability.
func (s IPPortSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ipp)
}

// UnmarshalJSON unmarshals s from JSON.
// It is necessary so that IPPortSet's fields can be unexported, to guarantee immutability.
func (s *IPPortSet) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &s.ipp)
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

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package endpoint contains types relating to UDP relay server endpoints. It
// does not import tailscale.com/net/udprelay.
package endpoint

import (
	"net/netip"

	"tailscale.com/tstime"
	"tailscale.com/types/key"
)

// ServerEndpoint contains details for an endpoint served by a
// [tailscale.com/net/udprelay.Server].
type ServerEndpoint struct {
	// ServerDisco is the Server's Disco public key used as part of the 3-way
	// bind handshake. Server will use the same ServerDisco for its lifetime.
	// ServerDisco value in combination with LamportID value represents a
	// unique ServerEndpoint allocation.
	ServerDisco key.DiscoPublic

	// LamportID is unique and monotonically non-decreasing across
	// ServerEndpoint allocations for the lifetime of Server. It enables clients
	// to dedup and resolve allocation event order. Clients may race to allocate
	// on the same Server, and signal ServerEndpoint details via alternative
	// channels, e.g. DERP. Additionally, Server.AllocateEndpoint() requests may
	// not result in a new allocation depending on existing server-side endpoint
	// state. Therefore, where clients have local, existing state that contains
	// ServerDisco and LamportID values matching a newly learned endpoint, these
	// can be considered one and the same. If ServerDisco is equal, but
	// LamportID is unequal, LamportID comparison determines which
	// ServerEndpoint was allocated most recently.
	LamportID uint64

	// AddrPorts are the IP:Port candidate pairs the Server may be reachable
	// over.
	AddrPorts []netip.AddrPort

	// VNI (Virtual Network Identifier) is the Geneve header VNI the Server
	// will use for transmitted packets, and expects for received packets
	// associated with this endpoint.
	VNI uint32

	// BindLifetime is amount of time post-allocation the Server will consider
	// the endpoint active while it has yet to be bound via 3-way bind handshake
	// from both client parties.
	BindLifetime tstime.GoDuration

	// SteadyStateLifetime is the amount of time post 3-way bind handshake from
	// both client parties the Server will consider the endpoint active lacking
	// bidirectional data flow.
	SteadyStateLifetime tstime.GoDuration
}

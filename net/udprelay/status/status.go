// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package status contains types relating to the status of peer relay sessions
// between peer relay client nodes via a peer relay server.
package status

import (
	"fmt"
	"net/netip"
)

// ServerState is the current state of the peer relay server extension.
type ServerState int

const (
	// Uninitialized indicates the peer relay server hasn't been initialized
	// yet on this node. It does NOT imply the peer relay server can be
	// initialized for this node; the node may not be configured as a peer
	// relay server yet, or may be disabled by node attribute.
	Uninitialized ServerState = iota
	// NotConfigured indicates the peer relay server port has not been set for
	// this node; a node cannot be a peer relay server until the port has been
	// set.
	NotConfigured
	// Disabled indicates the peer relay server has been disabled by a node
	// attribute pushed via C2N.
	Disabled
	// Running indicates the peer relay server has been initialized and can
	// relay sessions between peers on the configured UDP port.
	Running
	// ShutDown indicates the peer relay server extension has been told to
	// shut down, and can no longer relay sessions between peers.
	ShutDown
)

// ServerStatus contains the listening UDP port, state, and active sessions (if
// any) for this node's peer relay server at a point in time.
type ServerStatus struct {
	// State is the current phase/state in the peer relay server's state
	// machine. See [ServerState].
	State ServerState
	// UDPPort is the UDP port number that the peer relay server is listening
	// for incoming peer relay endpoint allocation requests on, as configured
	// by the user with 'tailscale set --relay-server-port=<PORT>'. If State is
	// [NotConfigured], this field will be -1.
	UDPPort int
	// Sessions is an array of detailed status information about each peer
	// relay session that this node's peer relay server is involved with. It
	// may be empty.
	Sessions []ServerSession
}

// ServerInfo contains status-related information about the peer relay server
// involved in a single peer relay session.
type ServerInfo struct {
	// Endpoint is the [netip.AddrPort] for the peer relay server's underlay
	// endpoint participating in the session. Both clients in a session are
	// bound into the same endpoint on the server. This may be invalid; check
	// the value with [netip.AddrPort.IsValid] before using.
	Endpoint netip.AddrPort
	// ShortDisco is a string representation of the peer relay server's disco
	// public key. This can be the empty string.
	ShortDisco string
}

// String returns a string representation of the [ServerInfo] containing the
// endpoint address/port and short disco public key.
func (i *ServerInfo) String() string {
	disco := i.ShortDisco
	if disco == "" {
		disco = "[d:unknown]"
	}

	if i.Endpoint.IsValid() {
		return fmt.Sprintf("%v[%s]", i.Endpoint, disco)
	} else {
		return fmt.Sprintf("unknown[%s]", disco)
	}
}

// ClientInfo contains status-related information about a single peer relay
// client involved in a single peer relay session.
type ClientInfo struct {
	// Endpoint is the [netip.AddrPort] of this peer relay client's underlay
	// endpoint participating in the session. This may be invalid; check the
	// value with [netip.AddrPort.IsValid] before using.
	Endpoint netip.AddrPort
	// ShortDisco is a string representation of this peer relay client's disco
	// public key. This can be the empty string.
	ShortDisco string
	// PacketsTx is the number of packets this peer relay client has sent to
	// the other client via the relay server after completing session
	// establishment. This is identical to the number of packets that the peer
	// relay server has received from this client.
	PacketsTx uint64
	// BytesTx is the total overlay bytes this peer relay client has sent to
	// the other client via the relay server after completing session
	// establishment. This is identical to the total overlay bytes that the
	// peer relay server has received from this client.
	BytesTx uint64
}

// String returns a string representation of the [ClientInfo] containing the
// endpoint address/port, short disco public key, and packet/byte counts.
func (i *ClientInfo) String() string {
	disco := i.ShortDisco
	if disco == "" {
		disco = "[d:unknown]"
	}

	if i.Endpoint.IsValid() {
		return fmt.Sprintf("%v[%s] tx %v(%vB)", i.Endpoint, i.ShortDisco, i.PacketsTx, i.BytesTx)
	} else {
		return fmt.Sprintf("unknown[%s] tx %v(%vB)", disco, i.PacketsTx, i.BytesTx)
	}
}

// ServerSession contains status information for a single session between two
// peer relay clients, which are relayed via one peer relay server. This is the
// status as seen by the peer relay server; each client node may have a
// different view of the session's current status based on connectivity and
// where the client is in the peer relay endpoint setup (allocation, binding,
// pinging, active).
type ServerSession struct {
	// Status is the current state of the session, as seen by the peer relay
	// server. It contains the status of each phase of session setup and usage:
	// endpoint allocation, endpoint binding, disco ping/pong, and active.
	Status SessionStatus
	// VNI is the Virtual Network Identifier for this peer relay session, which
	// comes from the Geneve header and is unique to this session.
	VNI uint32
	// Server contains status information about the peer relay server involved
	// in this session.
	Server ServerInfo
	// Client1 contains status information about one of the two peer relay
	// clients involved in this session. Note that 'Client1' does NOT mean this
	// was/wasn't the allocating client, or the first client to bind, etc; this
	// is just one client of two.
	Client1 ClientInfo
	// Client2 contains status information about one of the two peer relay
	// clients involved in this session. Note that 'Client2' does NOT mean this
	// was/wasn't the allocating client, or the second client to bind, etc;
	// this is just one client of two.
	Client2 ClientInfo
}

// SessionStatus is the current state of a peer relay session, as seen by the
// peer relay server that's relaying the session.
type SessionStatus int

const (
	// NotStarted is the default "unknown" state for a session; it should not
	// be seen outside of initialization.
	NotStarted SessionStatus = iota
	// Allocating indicates a peer relay client has contacted the peer relay
	// server with a valid endpoint allocation request, and the server is in
	// the process of allocating it. A session remains in this state until one
	// of the two clients begins the Binding process.
	Allocating
	// Binding indicates at least one of the two peer relay clients has started
	// the endpoint binding handshake with the peer relay server's endpoint for
	// this session. A session remains in this state until both clients have
	// completed the binding handshake and are bound into the endpoint.
	Binding
	// Pinging indicates the two peer relay clients should be sending disco
	// ping/pong messages to one another to confirm peer relay session
	// connectivity via the peer relay server endpoint. We don't actually
	// monitor the disco ping/pong messages between the clients; we move into
	// this state when Binding is complete, and move out of this state to
	// [Active] when we see packets being exchanged bidirectionally over the
	// session endpoint. As such, Pinging is currently an implicit intermediate
	// state rather than a "confirmed by looking at disco ping/pong" state.
	Pinging
	// Active indicates the peer relay clients are both bound into the peer
	// relay session, have completed their disco pinging process, and are
	// bidirectionally exchanging packets via the peer relay server.
	Active
)

// String returns a short, human-readable string representation of the current
// [SessionStatus].
func (s SessionStatus) String() string {
	switch s {
	case Allocating:
		return "allocating endpoint"
	case Binding:
		return "binding endpoint"
	case Pinging:
		return "clients pinging"
	case Active:
		return "session active"
	default:
		return "unknown"
	}
}

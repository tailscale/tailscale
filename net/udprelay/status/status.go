// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package status contains types relating to the status of peer relay sessions
// between peer relay client nodes via a peer relay server.
package status

import (
	"net/netip"
)

// ServerStatus contains the listening UDP port and active sessions (if any) for
// this node's peer relay server at a point in time.
type ServerStatus struct {
	// UDPPort is the UDP port number that the peer relay server forwards over,
	// as configured by the user with 'tailscale set --relay-server-port=<PORT>'.
	// If the port has not been configured, UDPPort will be nil.
	UDPPort *int
	// Sessions is a slice of detailed status information about each peer
	// relay session that this node's peer relay server is involved with. It
	// may be empty.
	Sessions []ServerSession
}

// ClientInfo contains status-related information about a single peer relay
// client involved in a single peer relay session.
type ClientInfo struct {
	// Endpoint is the [netip.AddrPort] of this peer relay client's underlay
	// endpoint participating in the session, or a zero value if the client
	// has not completed a handshake.
	Endpoint netip.AddrPort
	// ShortDisco is a string representation of this peer relay client's disco
	// public key.
	//
	// TODO: disco keys are pretty meaningless to end users, and they are also
	//  ephemeral. We really need node keys (or translation to first ts addr),
	//  but those are not fully plumbed into the [udprelay.Server]. Disco keys
	//  can also be ambiguous to a node key, but we could add node key into a
	//  [disco.AllocateUDPRelayEndpointRequest] in similar fashion to
	//  [disco.Ping]. There's also the problem of netmap trimming, where we
	//  can't verify a node key maps to a disco key.
	ShortDisco string
	// PacketsTx is the number of packets this peer relay client has sent to
	// the other client via the relay server after completing a handshake. This
	// is identical to the number of packets that the peer relay server has
	// received from this client.
	PacketsTx uint64
	// BytesTx is the total overlay bytes this peer relay client has sent to
	// the other client via the relay server after completing a handshake. This
	// is identical to the total overlay bytes that the peer relay server has
	// received from this client.
	BytesTx uint64
}

// ServerSession contains status information for a single session between two
// peer relay clients, which are relayed via one peer relay server. This is the
// status as seen by the peer relay server; each client node may have a
// different view of the session's current status based on connectivity and
// where the client is in the peer relay endpoint setup (allocation, binding,
// pinging, active).
type ServerSession struct {
	// VNI is the Virtual Network Identifier for this peer relay session, which
	// comes from the Geneve header and is unique to this session.
	VNI uint32
	// Client1 contains status information about one of the two peer relay
	// clients involved in this session. Note that 'Client1' does NOT mean this
	// was/wasn't the allocating client, or the first client to bind, etc; this
	// is just one client of two.
	Client1 ClientInfo
	// Client2 contains status information about one of the two peer relay
	// clients involved in this session. Note that 'Client2' does NOT mean this
	// was/wasn't the allocating client, or the second client to bind, etc; this
	// is just one client of two.
	Client2 ClientInfo
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package endpoint contains types relating to UDP relay server endpoints. It
// does not import tailscale.com/net/udprelay.
package endpoint

import (
	"net/netip"
	"time"

	"tailscale.com/tstime"
	"tailscale.com/types/key"
)

// ServerRetryAfter is the default
// [tailscale.com/net/udprelay.ErrServerNotReady.RetryAfter] value.
const ServerRetryAfter = time.Second * 3

// ServerEndpoint contains details for an endpoint served by a
// [tailscale.com/net/udprelay.Server].
type ServerEndpoint struct {
	// ServerDisco is the Server's Disco public key used as part of the 3-way
	// bind handshake. Server will use the same ServerDisco for its lifetime.
	// ServerDisco value in combination with LamportID value represents a
	// unique ServerEndpoint allocation.
	ServerDisco key.DiscoPublic

	// ClientDisco are the Disco public keys of the relay participants permitted
	// to handshake with this endpoint.
	ClientDisco [2]key.DiscoPublic

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

// TODO (dylan): doc comments
type PeerRelayServerAllocStatus int

const (
	EndpointAllocNotStarted PeerRelayServerAllocStatus = iota
	// EndpointAllocRequestReceived by the peer relay server from the allocating client
	EndpointAllocRequestReceived
	// EndpointAllocated on the peer relay server, but response not yet sent to allocating client
	EndpointAllocated
	// EndpointAllocResponseSent from the peer relay server to allocating client
	EndpointAllocResponseSent

	// TODO (dylan): Should we have a status here for dead allocs that weren't bound before the
	// BindLifetime timer expired?
	EndpointAllocExpired
)

func (s PeerRelayServerAllocStatus) String() string {
	switch s {
	case EndpointAllocNotStarted:
		return "alloc not started"
	case EndpointAllocRequestReceived:
		return "alloc request received"
	case EndpointAllocated:
		return "endpoint allocated"
	case EndpointAllocResponseSent:
		return "alloc complete"
	case EndpointAllocExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// PeerRelayServerBindStatus is the current status of the endpoint binding
// handshake between the peer relay server and a SINGLE peer relay client. Both
// clients need to bind into an endpoint for a peer relay session to be bound,
// so a peer relay server will have two PeerRelayServerBindStatus fields to
// track per session.
type PeerRelayServerBindStatus int

// TODO (dylan): doc comments
const (
	EndpointBindNotStarted PeerRelayServerBindStatus = iota
	EndpointBindRequestReceived
	EndpointBindChallengeSent
	EndpointBindAnswerReceived
)

func (s PeerRelayServerBindStatus) String() string {
	switch s {
	case EndpointBindNotStarted:
		return "binding not started"
	case EndpointBindRequestReceived:
		return "bind request received"
	case EndpointBindChallengeSent:
		return "bind challenge sent"
	case EndpointBindAnswerReceived:
		return "bind complete"
	default:
		return "unknown"
	}
}

// PeerRelayServerPingStatus is the current status of a SINGLE SIDE of the
// bidirectional disco ping exchange between two peer relay clients, as seen by
// the peer relay server. As each client will send a disco ping and should
// receive a disco pong from the other client in response, a peer relay server
// will have two PeerRelayServerPingStatus fields to track per session.
type PeerRelayServerPingStatus int

// TODO (dylan): doc comments
const (
	DiscoPingNotStarted PeerRelayServerPingStatus = iota
	DiscoPingSeen
	DiscoPongSeen
)

func (s PeerRelayServerPingStatus) String() string {
	switch s {
	case DiscoPingNotStarted:
		return "ping not started"
	case DiscoPingSeen:
		return "disco ping seen"
	case DiscoPongSeen:
		return "disco pong seen"
	default:
		return "unknown"
	}
}

// TODO (dylan): doc comments
type PeerRelayServerStatus int

// TODO (dylan): doc comments
const (
	AllocatingEndpoint PeerRelayServerStatus = iota
	BindingEndpoint
	BidirectionalPinging
	ServerSessionEstablished
)

func (s PeerRelayServerStatus) String() string {
	switch s {
	case AllocatingEndpoint:
		return "allocating endpoint allocation"
	case BindingEndpoint:
		return "binding endpoint"
	case BidirectionalPinging:
		return "clients pinging"
	case ServerSessionEstablished:
		return "session established"
	default:
		return "unknown"
	}
}

// TODO (dylan): doc comments
type PeerRelayServerSessionStatus struct {
	AllocStatus      PeerRelayServerAllocStatus
	ClientBindStatus [2]PeerRelayServerBindStatus
	ClientPingStatus [2]PeerRelayServerPingStatus
	ClientPacketsRx  [2]uint64
	ClientPacketsFwd [2]uint64

	OverallStatus PeerRelayServerStatus
}

func NewPeerRelayServerSessionStatus() PeerRelayServerSessionStatus {
	return PeerRelayServerSessionStatus{
		AllocStatus:      EndpointAllocNotStarted,
		ClientBindStatus: [2]PeerRelayServerBindStatus{EndpointBindNotStarted, EndpointBindNotStarted},
		ClientPingStatus: [2]PeerRelayServerPingStatus{DiscoPingNotStarted, DiscoPingNotStarted},
		OverallStatus:    AllocatingEndpoint,
	}
}

// TODO (dylan): doc comments
type PeerRelayClientAllocStatus int

const (
	// EndpointAllocRequestSent from the allocating client to the peer relay server via DERP
	EndpointAllocRequestSent PeerRelayClientAllocStatus = iota
	// EndpointAllocResponseReceived by the allocating client from the peer relay server via DERP
	EndpointAllocResponseReceived
	// CallMeMaybeViaSent from the allocating client to the target client via DERP
	CallMeMaybeViaSent
	// CallMeMaybeViaReceived by the target client from the allocating client via DERP
	CallMeMaybeViaReceived
)

// TODO (dylan): doc comments
type PeerRelayClientBindStatus int

const (
	// EndpointBindHandshakeSent from this client to the peer relay server
	EndpointBindHandshakeSent PeerRelayClientBindStatus = iota
	// EndpointBindChallengeReceived by this client from the peer relay server
	EndpointBindChallengeReceived
	// EndpointBindAnswerSent from this client to the peer relay server
	EndpointBindAnswerSent
)

// TODO (dylan): doc comments
type PeerRelayClientPingStatus int

// TODO (dylan): doc comments
const (
	DiscoPingSent PeerRelayClientPingStatus = iota
	DiscoPingReceived
)

// TODO (dylan): doc comments
type PeerRelayClientStatus int

// TODO (dylan): doc comments
const (
	EndpointAllocation PeerRelayClientStatus = iota
	EndpointBinding
	Pinging
	ClientSessionEstablished
)

// TODO (dylan): doc comments
type PeerRelayClientSessionStatus struct {
	AllocStatus PeerRelayClientAllocStatus
	BindStatus  PeerRelayClientBindStatus
	PingStatus  PeerRelayClientPingStatus

	OverallStatus PeerRelayClientStatus
}

// TODO (dylan): doc comments
type PeerRelaySessionBaseStatus struct {
	VNI              uint32
	ClientShortDisco [2]string
	ClientEndpoint   [2]netip.AddrPort
	ServerShortDisco string
	ServerEndpoint   netip.AddrPort
}

// TODO (dylan): doc comments
type PeerRelayServerSession struct {
	Status PeerRelayServerSessionStatus
	PeerRelaySessionBaseStatus
}

// TODO (dylan): doc comments
type PeerRelayClientSession struct {
	Status PeerRelayClientStatus
	PeerRelaySessionBaseStatus
}

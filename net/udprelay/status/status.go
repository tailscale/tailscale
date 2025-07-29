// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package status contains types relating to the status of peer relay sessions
// between nodes via a peer relay server.
package status

import "net/netip"

// ServerSession contains status information for a single session between two
// peer relay clients relayed via a peer relay server. This is the status as
// seen by the peer relay server; each client node may have a different view of
// the session's current status.
type ServerSession struct {
	// Status is the current state of the session, as seen by the peer relay
	// server. It contains the status of each phase of session setup and usage:
	// endpoint allocation, endpoint binding, disco ping/pong, and active.
	// TODO (dylan): confirm these statuses/state machines
	Status SessionStatus
	// VNI is the Virtual Network Identifier for this peer relay session, which
	// comes from the Geneve header and is unique to this session.
	VNI uint32
	// ClientShortDisco is a string representation of each peer relay client's
	// disco public key (one string for each of the two clients).
	// TODO (dylan): can either of these ever be nil?
	ClientShortDisco [2]string
	// ClientEndpoint is the [netip.AddrPort] of each peer relay client's
	// endpoint participating in the session (one endpoint for each of the two
	// clients).
	// TODO (dylan): can either of these ever be nil?
	ClientEndpoint [2]netip.AddrPort
	// ServerShortDisco is a string representation of the peer relay server's
	// disco public key.
	// TODO (dylan): can there be a different disco key per-client?
	ServerShortDisco string
	// ServerEndpoint is the [netip.AddrPort] for the peer relay server's
	// endpoint participating in the session (one endpoint for each of the two
	// clients).
	// TODO (dylan): can there be a different endpoint per-client?
	ServerEndpoint netip.AddrPort
}

// TODO (dylan): doc comments
type SessionStatus struct {
	AllocStatus      AllocStatus
	ClientBindStatus [2]BindStatus
	ClientPingStatus [2]PingStatus
	ClientPacketsRx  [2]uint64
	ClientPacketsFwd [2]uint64

	OverallStatus OverallSessionStatus
}

// TODO (dylan): doc comments
func NewSessionStatus() SessionStatus {
	return SessionStatus{
		AllocStatus:      EndpointAllocNotStarted,
		ClientBindStatus: [2]BindStatus{EndpointBindNotStarted, EndpointBindNotStarted},
		ClientPingStatus: [2]PingStatus{DiscoPingNotStarted, DiscoPingNotStarted},
		OverallStatus:    Allocating,
	}
}

// TODO (dylan): doc comments
type AllocStatus int

// TODO (dylan): doc comments
const (
	EndpointAllocNotStarted AllocStatus = iota
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

func (s AllocStatus) String() string {
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

// BindStatus is the current status of the endpoint binding handshake between
// the peer relay server and a SINGLE peer relay client. Both clients need to
// bind into an endpoint for a peer relay session to be bound, so a peer relay
// server will have two BindStatus fields to track per session.
type BindStatus int

// TODO (dylan): doc comments
const (
	EndpointBindNotStarted BindStatus = iota
	EndpointBindRequestReceived
	EndpointBindChallengeSent
	EndpointBindAnswerReceived
)

func (s BindStatus) String() string {
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

// PingStatus is the current status of a SINGLE SIDE of the
// bidirectional disco ping exchange between two peer relay clients, as seen by
// the peer relay server. As each client will send a disco ping and should
// receive a disco pong from the other client in response, a peer relay server
// will have two PingStatus fields to track per session.
type PingStatus int

// TODO (dylan): doc comments
const (
	DiscoPingNotStarted PingStatus = iota
	DiscoPingSeen
	DiscoPongSeen
)

// TODO (dylan): doc comments
func (s PingStatus) String() string {
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
type OverallSessionStatus int

// TODO (dylan): doc comments
const (
	NotStarted OverallSessionStatus = iota
	Allocating
	Binding
	Pinging
	Established
	Idle
)

// String returns a short, human-readable string representation of the current
// [OverallSessionStatus].
func (s OverallSessionStatus) String() string {
	switch s {
	case Allocating:
		return "allocating endpoint"
	case Binding:
		return "binding endpoint"
	case Pinging:
		return "clients pinging"
	case Established:
		return "session established"
	default:
		return "unknown"
	}
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnstate

import (
	"time"

	"tailscale.com/types/key"
)

// DebugActiveEndpoints describes, per peer, the active dataplane endpoint
// state as seen by both magicsock and wireguard-go. It is the response type
// of the "debug-active-endpoints" LocalAPI endpoint, the
// "/debug/active-endpoints" c2n endpoint, and the
// "tailscale debug active-endpoints" CLI command.
//
// It is a debug API intended for debugging dataplane issues (e.g. a stale
// wireguard-go peer endpoint black-holing traffic, see
// tailscale/tailscale#20082) and for test assertions about a client's
// expected dataplane state. Its contents are subject to change.
type DebugActiveEndpoints struct {
	// Peers describes each peer's active endpoint state, sorted by node key.
	Peers []PeerActiveEndpoints `json:",omitempty"`
}

// PeerActiveEndpoints describes a single peer's active dataplane endpoint
// state, as seen by both magicsock and wireguard-go.
type PeerActiveEndpoints struct {
	// NodeKey is the peer's node (WireGuard) public key.
	NodeKey key.NodePublic

	// ShortDisco is the short form of the peer's disco key, if known.
	ShortDisco string `json:",omitempty"`

	// Magicsock describes the peer's magicsock endpoint state. It is nil
	// if the peer is not present in magicsock's peer map.
	Magicsock *MagicsockEndpointState `json:",omitempty"`

	// WireGuard describes the peer's state as seen by wireguard-go. It is
	// nil if wireguard-go does not currently have the peer configured;
	// wireguard-go peers are created lazily upon first packet exchanged
	// with the peer.
	WireGuard *WireGuardPeerState `json:",omitempty"`
}

// MagicsockEndpointState describes a peer's active endpoint state as seen by
// magicsock.
type MagicsockEndpointState struct {
	// BestAddr is the current best (non-DERP) path to the peer as
	// "ip:port", suffixed with ":vni:<n>" if the path traverses a UDP peer
	// relay. It is empty if magicsock has no UDP path to the peer.
	BestAddr string `json:",omitempty"`

	// BestAddrTrusted reports whether BestAddr is currently trusted for
	// sending, i.e. it has been confirmed recently enough via pong
	// reception. When false and BestAddr is nonempty, magicsock sends to
	// both BestAddr and DERPAddr while it re-confirms the path.
	BestAddrTrusted bool `json:",omitzero"`

	// BestAddrAt is the time at which BestAddr was last (re-)confirmed.
	BestAddrAt time.Time `json:",omitzero"`

	// TrustBestAddrUntil is the time at which trust of BestAddr expires.
	TrustBestAddrUntil time.Time `json:",omitzero"`

	// DERPAddr is the peer's fallback/bootstrap DERP pseudo-address
	// ("127.3.3.40:<region-id>"), if any.
	DERPAddr string `json:",omitempty"`

	// DERPRegion is the peer's home DERP region ID, if any.
	DERPRegion int `json:",omitzero"`

	// LastSend is the last time a packet was sent to the peer from an
	// external trigger (wireguard-go or a disco CLI ping), if ever.
	LastSend time.Time `json:",omitzero"`

	// LastRecv is the last time a UDP packet of any kind, including
	// disco, was received from the peer, if ever. It does not include
	// packets received via DERP.
	LastRecv time.Time `json:",omitzero"`

	// LastRecvWG is the last time a packet destined for wireguard-go
	// (i.e. data, not disco) was received from the peer, if ever. Unlike
	// LastRecv it excludes disco traffic, so it answers whether WireGuard
	// data is still arriving from the peer even while sends to it are
	// black-holed (tailscale/tailscale#20082).
	LastRecvWG time.Time `json:",omitzero"`

	// LastFullPing is the last time magicsock pinged all of the peer's
	// candidate endpoints, if ever.
	LastFullPing time.Time `json:",omitzero"`

	// EpAddrCount is the number of "ip:port" (+ optional VNI) addresses
	// mapped to this peer in magicsock's peer map.
	EpAddrCount int `json:",omitzero"`

	// IsWireGuardOnly is whether the peer is a WireGuard-only peer (it
	// does not speak disco, e.g. a Mullvad exit node). For such peers
	// there is no disco path discovery: ShortDisco is empty and
	// trust/ping-related fields should be interpreted accordingly.
	IsWireGuardOnly bool `json:",omitzero"`

	// Expired is whether the peer's node key has expired. Magicsock does
	// not send to or accept new paths from expired peers, so the other
	// fields describe only historical state.
	Expired bool `json:",omitzero"`
}

// Values of [WireGuardPeerState].EndpointType.
const (
	// WireGuardEndpointTypeMagicsock indicates wireguard-go holds the
	// magicsock-managed endpoint for the peer.
	WireGuardEndpointTypeMagicsock = "magicsock"
	// WireGuardEndpointTypeOther indicates wireguard-go holds some other
	// endpoint for the peer, e.g. a stale magicsock lazy endpoint.
	WireGuardEndpointTypeOther = "other"
)

// WireGuardPeerState describes a peer's state as seen by wireguard-go. Its
// presence alone indicates that a wireguard-go peer currently exists;
// wireguard-go peers are created lazily upon first packet exchanged with the
// peer.
type WireGuardPeerState struct {
	// Endpoint is the string form (DstToString) of the endpoint that
	// wireguard-go currently holds for the peer, exactly as wireguard-go
	// would report it. A magicsock-managed endpoint renders as the peer's
	// node public key in untyped hex; anything else (e.g. magicsock's
	// lazyEndpoint) renders as "ip:port", suffixed with ":vni:<n>" if the
	// path traverses a UDP peer relay. It is empty if wireguard-go holds
	// no endpoint for the peer.
	Endpoint string `json:",omitempty"`

	// EndpointType classifies the endpoint that wireguard-go currently
	// holds for the peer, by its concrete type:
	// [WireGuardEndpointTypeMagicsock] when wireguard-go holds the
	// magicsock-managed endpoint for the peer, or
	// [WireGuardEndpointTypeOther] when it holds anything else, which may
	// indicate a problem, e.g. a stale lazy endpoint black-holing traffic
	// (tailscale/tailscale#20082). It is empty if wireguard-go holds no
	// endpoint for the peer.
	EndpointType string `json:",omitempty"`

	// LastHandshake is the time of the last completed WireGuard handshake
	// with the peer, if ever.
	LastHandshake time.Time `json:",omitzero"`

	// RxBytes is the number of bytes received from the peer.
	RxBytes uint64 `json:",omitzero"`

	// TxBytes is the number of bytes sent to the peer.
	TxBytes uint64 `json:",omitzero"`
}

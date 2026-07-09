// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wgengine provides the Tailscale WireGuard engine interface.
package wgengine

import (
	"errors"
	"net/netip"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgint"
)

// Status is the Engine status.
//
// TODO(bradfitz): remove this, subset of ipnstate? Need to migrate users.
type Status struct {
	AsOf       time.Time // the time at which the status was calculated
	Peers      []ipnstate.PeerStatusLite
	LocalAddrs []tailcfg.Endpoint // the set of possible endpoints for the magic conn
	DERPs      int                // number of active DERP connections
}

// StatusCallback is the type of status callbacks used by
// Engine.SetStatusCallback.
//
// Exactly one of Status or error is non-nil.
type StatusCallback func(*Status, error)

// NetworkMapCallback is the type used by callbacks that hook
// into network map updates.
type NetworkMapCallback func(*netmap.NetworkMap)

// PeerWireGuardState is the current WireGuard session state for a peer.
type PeerWireGuardState uint8

const (
	// PeerWireGuardStateNone means there is no handshake in progress and no
	// session key material retained for this peer.
	PeerWireGuardStateNone PeerWireGuardState = 0

	// PeerWireGuardStateHandshake means a handshake is in progress for this
	// peer, but there is not currently a usable WireGuard session.
	PeerWireGuardStateHandshake PeerWireGuardState = 1

	// PeerWireGuardStateEstablished means the peer has a completed WireGuard
	// session with usable session key material.
	PeerWireGuardStateEstablished PeerWireGuardState = 2

	// PeerWireGuardStateExpired means the peer's session key material is no
	// longer considered usable, but final key cleanup or lazy peer removal may
	// not have happened yet.
	PeerWireGuardStateExpired PeerWireGuardState = 3
)

// ErrNoChanges is returned by Engine.Reconfig if no changes were made.
var ErrNoChanges = errors.New("no changes made to Engine config")

// PeerForIP is the type returned by Engine.PeerForIP.
type PeerForIP struct {
	// Node is the matched node. It's always a valid value when
	// Engine.PeerForIP returns ok==true.
	Node tailcfg.NodeView

	// IsSelf is whether the Node is the local process.
	IsSelf bool

	// Route is the route that matched the IP provided
	// to Engine.PeerForIP.
	Route netip.Prefix
}

// Engine is the Tailscale WireGuard engine interface.
type Engine interface {
	// Reconfig reconfigures WireGuard and makes sure it's running.
	// This also handles setting up any kernel routes.
	//
	// This is called whenever tailcontrol (the control plane)
	// sends an updated network map.
	//
	// The returned error is ErrNoChanges if no changes were made.
	Reconfig(*wgcfg.Config, *router.Config, *dns.Config) error

	// ResetAndStop resets the engine to a clean state (like calling Reconfig
	// with all pointers to zero values) and waits for it to be fully stopped,
	// with no live peers or DERPs.
	//
	// Unlike Reconfig, it does not return ErrNoChanges.
	ResetAndStop() (*Status, error)

	// PeerForIP returns the node to which the provided IP routes,
	// if any. If none is found, (zero, false) is returned.
	//
	// Despite the name, it can return the self node (with
	// PeerForIP.IsSelf set). It handles Tailscale IPs, subnet-routed
	// IPs, and exit-node global internet IPs, returning whichever
	// node would handle that traffic.
	//
	// This is the cold path used by Ping, TSMP, pendopen diagnostics,
	// and debug endpoints. It uses the same underlying data structures
	// as the wireguard-go outbound packet path
	// ([Engine.SetPeerByIPPacketFunc]), but is slower because it
	// returns richer data (a full NodeView, the matched route prefix,
	// and the IsSelf flag) requiring extra lookups.
	//
	// In production, the lookup is implemented by LocalBackend and
	// plumbed in via [Engine.SetPeerForIPFunc]; the engine itself holds
	// no peer-lookup state on this path.
	PeerForIP(netip.Addr) (_ PeerForIP, ok bool)

	// SetPeerForIPFunc installs a callback used by [Engine.PeerForIP].
	// It parallels [Engine.SetPeerByIPPacketFunc] but serves the
	// cold-path control lookups (Ping, TSMP, pendopen diagnostics,
	// [tsdial.Dialer.UseNetstackForIP], debug endpoints).
	//
	// If fn is nil, PeerForIP returns (zero, false) for every IP.
	//
	// LocalBackend installs a func backed by the live nodeBackend for
	// exact-match and self addresses, with [Engine.PeerKeyForIP]
	// supplying the subnet-route / exit-node fallback.
	SetPeerForIPFunc(fn func(netip.Addr) (_ PeerForIP, ok bool))

	// PeerKeyForIP returns the peer's NodePublic and the matched prefix
	// for the longest-prefix match of ip in the engine's AllowedIPs
	// table (the wireguard config most recently installed via
	// [Engine.Reconfig]). Exit-node selection is honored: an unselected
	// exit node's 0.0.0.0/0 is not matched. It is the same table the
	// outbound packet hot path consults via [Engine.SetPeerByIPPacketFunc].
	PeerKeyForIP(netip.Addr) (_ key.NodePublic, _ netip.Prefix, ok bool)

	// GetFilter returns the current packet filter, if any.
	GetFilter() *filter.Filter

	// SetFilter updates the packet filter.
	SetFilter(*filter.Filter)

	// GetJailedFilter returns the current packet filter for jailed nodes,
	// if any.
	GetJailedFilter() *filter.Filter

	// SetJailedFilter updates the packet filter for jailed nodes.
	SetJailedFilter(*filter.Filter)

	// SetStatusCallback sets the function to call when the
	// WireGuard status changes.
	SetStatusCallback(StatusCallback)

	// RequestStatus requests a WireGuard status update right
	// away, sent to the callback registered via SetStatusCallback.
	RequestStatus()

	// PeerByKey returns the WireGuard status of the provided peer.
	// If the peer is not found, ok is false.
	PeerByKey(key.NodePublic) (_ wgint.Peer, ok bool)

	// Close shuts down this wireguard instance, remove any routes
	// it added, etc. To bring it up again later, you'll need a
	// new Engine.
	Close()

	// Done returns a channel that is closed when the Engine's
	// Close method is called, the engine aborts with an error,
	// or it shuts down due to the closure of the underlying device.
	// You don't have to call this.
	Done() <-chan struct{}

	// SetSelfNode informs the engine of the current self node.
	// The zero (invalid) NodeView indicates no self node.
	SetSelfNode(tailcfg.NodeView)

	// UpdateStatus populates the network state using the provided
	// status builder.
	UpdateStatus(*ipnstate.StatusBuilder)

	// Ping is a request to start a ping of the given message size to the peer
	// handling the given IP, then call cb with its ping latency & method.
	//
	// If size is zero too small, it is ignored. See tailscale.PingOpts for details.
	Ping(ip netip.Addr, pingType tailcfg.PingType, size int, cb func(*ipnstate.PingResult))

	// InstallCaptureHook registers a function to be called to capture
	// packets traversing the data path. The hook can be uninstalled by
	// calling this function with a nil value.
	InstallCaptureHook(packet.CaptureCallback)

	// SetPeerByIPPacketFunc installs a callback used by wireguard-go to
	// look up which peer should handle an outbound packet by destination IP.
	SetPeerByIPPacketFunc(func(netip.Addr) (_ key.NodePublic, ok bool))

	// SetNetLogSource installs the [NetLogSource] consulted by the
	// engine's network flow logger for node lookups and the current
	// audit logging identity.
	//
	// It is expected to be called once during LocalBackend construction,
	// before any [Engine.Reconfig] call that starts up the network logger.
	SetNetLogSource(NetLogSource)

	// SetWGPeerLookup installs the function used by the engine's
	// wireguard-go log wrapper to rewrite peer references in log lines
	// (mapping wireguard-go's "peer(XXXX…YYYY)" form to the
	// Tailscale-conventional short string form).
	//
	// It is expected to be called once during LocalBackend construction.
	// The function is called concurrently and must be safe to call with
	// no Engine locks held.
	SetWGPeerLookup(func(wgString string) (tsString string, ok bool))

	// SetPeerSessionStateFunc installs a callback used to observe WireGuard
	// peer session state transitions.
	//
	// Calls are serialized per Engine and delivered in transition order from
	// wireguard-go, while wireguard-go is holding locks. The callback must be
	// cheap and must not call back into wireguard-go.
	//
	// It does not replay current state. Callers that need a complete view should
	// set it before peers are started or lazily created, and maintain any
	// snapshots, sequence numbers, and pubsub state outside wireguard-go.
	//
	// In Tailscale, the usual implementation is
	// ipnlocal.LocalBackend.onPeerWireGuardState, installed early in
	// LocalBackend construction.
	SetPeerSessionStateFunc(func(key.NodePublic, PeerWireGuardState))

	// ProbeLocks acquires and releases the engine's internal locks so
	// that [ipnlocal.LocalBackend]'s watchdog can detect deadlocks in
	// the engine. It is otherwise a no-op.
	ProbeLocks()
}

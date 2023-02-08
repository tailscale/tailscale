// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"errors"
	"net/netip"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/capture"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
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

// NetInfoCallback is the type used by Engine.SetNetInfoCallback.
type NetInfoCallback func(*tailcfg.NetInfo)

// NetworkMapCallback is the type used by callbacks that hook
// into network map updates.
type NetworkMapCallback func(*netmap.NetworkMap)

// someHandle is allocated so its pointer address acts as a unique
// map key handle. (It needs to have non-zero size for Go to guarantee
// the pointer is unique.)
type someHandle struct{ _ byte }

// ErrNoChanges is returned by Engine.Reconfig if no changes were made.
var ErrNoChanges = errors.New("no changes made to Engine config")

// PeerForIP is the type returned by Engine.PeerForIP.
type PeerForIP struct {
	// Node is the matched node. It's always non-nil when
	// Engine.PeerForIP returns ok==true.
	Node *tailcfg.Node

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
	// The *tailcfg.Debug parameter can be nil.
	//
	// The returned error is ErrNoChanges if no changes were made.
	Reconfig(*wgcfg.Config, *router.Config, *dns.Config, *tailcfg.Debug) error

	// PeerForIP returns the node to which the provided IP routes,
	// if any. If none is found, (nil, false) is returned.
	PeerForIP(netip.Addr) (_ PeerForIP, ok bool)

	// GetFilter returns the current packet filter, if any.
	GetFilter() *filter.Filter

	// SetFilter updates the packet filter.
	SetFilter(*filter.Filter)

	// SetStatusCallback sets the function to call when the
	// WireGuard status changes.
	SetStatusCallback(StatusCallback)

	// GetLinkMonitor returns the link monitor.
	GetLinkMonitor() *monitor.Mon

	// RequestStatus requests a WireGuard status update right
	// away, sent to the callback registered via SetStatusCallback.
	RequestStatus()

	// Close shuts down this wireguard instance, remove any routes
	// it added, etc. To bring it up again later, you'll need a
	// new Engine.
	Close()

	// Wait waits until the Engine's Close method is called or the
	// engine aborts with an error. You don't have to call this.
	// TODO: return an error?
	Wait()

	// LinkChange informs the engine that the system network
	// link has changed.
	//
	// The isExpensive parameter is not used.
	//
	// LinkChange should be called whenever something changed with
	// the network, no matter how minor.
	//
	// Deprecated: don't use this method. It was removed shortly
	// before the Tailscale 1.6 release when we remembered that
	// Android doesn't use the Linux-based link monitor and has
	// its own mechanism that uses LinkChange. Android is the only
	// caller of this method now. Don't add more.
	LinkChange(isExpensive bool)

	// SetDERPMap controls which (if any) DERP servers are used.
	// If nil, DERP is disabled. It starts disabled until a DERP map
	// is configured.
	SetDERPMap(*tailcfg.DERPMap)

	// SetNetworkMap informs the engine of the latest network map
	// from the server. The network map's DERPMap field should be
	// ignored as as it might be disabled; get it from SetDERPMap
	// instead.
	// The network map should only be read from.
	SetNetworkMap(*netmap.NetworkMap)

	// AddNetworkMapCallback adds a function to a list of callbacks
	// that are called when the network map updates. It returns a
	// function that when called would remove the function from the
	// list of callbacks.
	AddNetworkMapCallback(NetworkMapCallback) (removeCallback func())

	// SetNetInfoCallback sets the function to call when a
	// new NetInfo summary is available.
	SetNetInfoCallback(NetInfoCallback)

	// DiscoPublicKey gets the public key used for path discovery
	// messages.
	DiscoPublicKey() key.DiscoPublic

	// UpdateStatus populates the network state using the provided
	// status builder.
	UpdateStatus(*ipnstate.StatusBuilder)

	// Ping is a request to start a ping with the peer handling the given IP and
	// then call cb with its ping latency & method.
	Ping(ip netip.Addr, pingType tailcfg.PingType, cb func(*ipnstate.PingResult))

	// RegisterIPPortIdentity registers a given node (identified by its
	// Tailscale IP) as temporarily having the given IP:port for whois lookups.
	// The IP:port is generally a localhost IP and an ephemeral port, used
	// while proxying connections to localhost when tailscaled is running
	// in netstack mode.
	RegisterIPPortIdentity(netip.AddrPort, netip.Addr)

	// UnregisterIPPortIdentity removes a temporary IP:port registration
	// made previously by RegisterIPPortIdentity.
	UnregisterIPPortIdentity(netip.AddrPort)

	// WhoIsIPPort looks up an IP:port in the temporary registrations,
	// and returns a matching Tailscale IP, if it exists.
	WhoIsIPPort(netip.AddrPort) (netip.Addr, bool)

	// InstallCaptureHook registers a function to be called to capture
	// packets traversing the data path. The hook can be uninstalled by
	// calling this function with a nil value.
	InstallCaptureHook(capture.Callback)
}

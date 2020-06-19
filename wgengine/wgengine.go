// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"errors"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/tsdns"
)

// ByteCount is the number of bytes that have been sent or received.
//
// TODO: why is this a type? remove?
// TODO: document whether it's payload bytes only or if it includes framing overhead.
type ByteCount int64

type PeerStatus struct {
	TxBytes, RxBytes ByteCount
	LastHandshake    time.Time
	NodeKey          tailcfg.NodeKey
}

// Status is the Engine status.
//
// TODO(bradfitz): remove this, subset of ipnstate? Need to migrate users.
type Status struct {
	Peers      []PeerStatus
	LocalAddrs []string // TODO(crawshaw): []wgcfg.Endpoint?
	DERPs      int      // number of active DERP connections
}

// StatusCallback is the type of status callbacks used by
// Engine.SetStatusCallback.
//
// Exactly one of Status or error is non-nil.
type StatusCallback func(*Status, error)

// NetInfoCallback is the type used by Engine.SetNetInfoCallback.
type NetInfoCallback func(*tailcfg.NetInfo)

// ErrNoChanges is returned by Engine.Reconfig if no changes were made.
var ErrNoChanges = errors.New("no changes made to Engine config")

// Engine is the Tailscale WireGuard engine interface.
type Engine interface {
	// Reconfig reconfigures WireGuard and makes sure it's running.
	// This also handles setting up any kernel routes.
	//
	// This is called whenever the tailcontrol (control plane)
	// sends an updated network map.

	//
	// The returned error is ErrNoChanges if no changes were made.
	Reconfig(*wgcfg.Config, *router.Config) error

	// GetFilter returns the current packet filter, if any.
	GetFilter() *filter.Filter

	// SetFilter updates the packet filter.
	SetFilter(*filter.Filter)

	// SetDNSMap updates the DNS map.
	SetDNSMap(*tsdns.Map)

	// SetStatusCallback sets the function to call when the
	// WireGuard status changes.
	SetStatusCallback(StatusCallback)

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
	// link has changed. The isExpensive parameter is set on links
	// where sending packets uses substantial power or money,
	// such as mobile data on a phone.
	//
	// LinkChange should be called whenever something changed with
	// the network, no matter how minor. The implementation should
	// look at the state of the network and decide whether the
	// change from before is interesting enough to warrant taking
	// action on.
	LinkChange(isExpensive bool)

	// SetDERPMap controls which (if any) DERP servers are used.
	// If nil, DERP is disabled. It starts disabled until a DERP map
	// is configured.
	SetDERPMap(*tailcfg.DERPMap)

	// SetNetInfoCallback sets the function to call when a
	// new NetInfo summary is available.
	SetNetInfoCallback(NetInfoCallback)

	// SetDiscoPrivateKey sets the private key used for path discovery
	// messages.
	SetDiscoPrivateKey(key.Private)

	// UpdateStatus populates the network state using the provided
	// status builder.
	UpdateStatus(*ipnstate.StatusBuilder)
}

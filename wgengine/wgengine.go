// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"fmt"
	"time"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
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

// RouteSettings is the full WireGuard config data (set of peers keys,
// IP, etc in wgcfg.Config) plus the things that WireGuard doesn't do
// itself, like DNS stuff.
type RouteSettings struct {
	LocalAddr  wgcfg.CIDR // TODO: why is this here? how does it differ from wgcfg.Config's info?
	DNS        []wgcfg.IP
	DNSDomains []string
	Cfg        *wgcfg.Config
}

// OnlyRelevantParts returns a string minimally describing the route settings.
func (rs *RouteSettings) OnlyRelevantParts() string {
	var peers [][]wgcfg.CIDR
	for _, p := range rs.Cfg.Peers {
		peers = append(peers, p.AllowedIPs)
	}
	return fmt.Sprintf("%v %v %v %v",
		rs.LocalAddr, rs.DNS, rs.DNSDomains, peers)
}

// NewUserspaceRouter returns a new Router for the current platform, using the provided tun device.
func NewUserspaceRouter(logf logger.Logf, wgdev *device.Device, tundev tun.Device) (Router, error) {
	return newUserspaceRouter(logf, wgdev, tundev)
}

// RouterGen is the signature for the two funcs that create Router implementations:
// NewUserspaceRouter (which varies by operating system) and NewFakeRouter.
type RouterGen func(logf logger.Logf, wgdev *device.Device, tundev tun.Device) (Router, error)

// Router is responsible for managing the system route table.
//
// There's only one instance, and one per-OS implementation.
type Router interface {
	// Up brings the router up.
	Up() error

	// SetRoutes is called regularly on network map updates.
	// It's how you kernel route table entries are populated for
	// each peer.
	SetRoutes(RouteSettings) error

	// Close closes the router.
	Close() error
}

// Engine is the Tailscale WireGuard engine interface.
type Engine interface {
	// Reconfig reconfigures WireGuard and makes sure it's running.
	// This also handles setting up any kernel routes.
	//
	// The provided DNS domains are not part of wgcfg.Config, as
	// WireGuard itself doesn't care about such things.
	//
	// This is called whenever the tailcontrol (control plane)
	// sends an updated network map.
	Reconfig(cfg *wgcfg.Config, dnsDomains []string) error

	// SetFilter updates the packet filter.
	SetFilter(*filter.Filter)

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

	// SetDERPEnabled controls whether DERP is enabled.
	// It starts enabled by default.
	SetDERPEnabled(bool)

	// SetNetInfoCallback sets the function to call when a
	// new NetInfo summary is available.
	SetNetInfoCallback(NetInfoCallback)
}

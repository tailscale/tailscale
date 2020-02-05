// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"fmt"
	"net"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

type ByteCount int64

type PeerStatus struct {
	TxBytes, RxBytes ByteCount
	LastHandshake    time.Time
	NodeKey          tailcfg.NodeKey
}

type Status struct {
	Peers      []PeerStatus
	LocalAddrs []string // TODO(crawshaw): []wgcfg.Endpoint?
}

type StatusCallback func(s *Status, err error)

type RouteSettings struct {
	LocalAddr  wgcfg.CIDR
	DNS        []net.IP
	DNSDomains []string
	Cfg        wgcfg.Config
}

// Only used on darwin for now
// TODO(apenwarr): This probably belongs in the darwinRouter struct.
var SetRoutesFunc func(rs RouteSettings) error

func (rs *RouteSettings) OnlyRelevantParts() string {
	var peers [][]wgcfg.CIDR
	for _, p := range rs.Cfg.Peers {
		peers = append(peers, p.AllowedIPs)
	}
	return fmt.Sprintf("%v %v %v %v",
		rs.LocalAddr, rs.DNS, rs.DNSDomains, peers)
}

type Router interface {
	Up() error
	SetRoutes(rs RouteSettings) error
	Close()
}

type Engine interface {
	// Reconfigure wireguard and make sure it's running.
	// This also handles setting up any kernel routes.
	Reconfig(cfg *wgcfg.Config, dnsDomains []string) error
	// Update the packet filter.
	SetFilter(filt *filter.Filter)
	// Set the function to call when wireguard status changes.
	SetStatusCallback(cb StatusCallback)
	// Request a wireguard status update right away, sent to the callback.
	RequestStatus()
	// Shut down this wireguard instance, remove any routes it added, etc.
	// To bring it up again later, you'll need a new Engine.
	Close()
	// Wait until the Engine is .Close()ed or aborts with an error.
	// You don't have to call this.
	Wait()
	// LinkChange informs the engine that the system network
	// link has changed. The isExpensive parameter is set on links
	// where sending packets uses substantial power or dollars
	// (such as LTE on a phone).
	LinkChange(isExpensive bool)
}

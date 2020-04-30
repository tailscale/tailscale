// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package router presents an interface to manipulate the host network
// stack's state.
package router

import (
	"fmt"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/types/logger"
)

// Router is responsible for managing the system network stack.
//
// There is typically only one instance of this interface per process.
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

// NewUserspaceRouter returns a new Router for the current platform, using the provided tun device.
func New(logf logger.Logf, wgdev *device.Device, tundev tun.Device) (Router, error) {
	return newUserspaceRouter(logf, wgdev, tundev)
}

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

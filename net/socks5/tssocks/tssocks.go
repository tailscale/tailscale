// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tssocks is the glue between Tailscale and the net/socks5 package.
package tssocks

import (
	"context"
	"net"
	"sync"

	"inet.af/netaddr"
	"tailscale.com/net/socks5"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
)

// NewServer returns a new SOCKS5 server configured to dial out to
// Tailscale addresses.
//
// The returned server is not yet listening. The caller must call
// Serve with a listener.
//
// If ns is non-nil, it is used for dialing when needed.
func NewServer(logf logger.Logf, e wgengine.Engine, ns *netstack.Impl) *socks5.Server {
	d := &dialer{ns: ns}
	e.AddNetworkMapCallback(d.onNewNetmap)
	return &socks5.Server{
		Logf:   logf,
		Dialer: d.DialContext,
	}
}

// dialer is the Tailscale SOCKS5 dialer.
type dialer struct {
	ns *netstack.Impl

	mu  sync.Mutex
	dns netstack.DNSMap
}

func (d *dialer) onNewNetmap(nm *netmap.NetworkMap) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dns = netstack.DNSMapFromNetworkMap(nm)
}

func (d *dialer) resolve(ctx context.Context, addr string) (netaddr.IPPort, error) {
	d.mu.Lock()
	dns := d.dns
	d.mu.Unlock()
	return dns.Resolve(ctx, addr)
}

func (d *dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ipp, err := d.resolve(ctx, addr)
	if err != nil {
		return nil, err
	}
	if d.ns != nil && d.useNetstackForIP(ipp.IP()) {
		return d.ns.DialContextTCP(ctx, ipp.String())
	}
	var stdDialer net.Dialer
	return stdDialer.DialContext(ctx, network, ipp.String())
}

func (d *dialer) useNetstackForIP(ip netaddr.IP) bool {
	if d.ns == nil {
		return false
	}
	// TODO(bradfitz): this isn't exactly right.
	// We should also support subnets when the
	// prefs are configured as such.
	return tsaddr.IsTailscaleIP(ip)
}

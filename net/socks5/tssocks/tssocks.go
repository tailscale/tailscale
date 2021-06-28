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
	srv := &socks5.Server{
		Logf: logf,
	}
	var (
		mu  sync.Mutex // guards the following field
		dns netstack.DNSMap
	)
	e.AddNetworkMapCallback(func(nm *netmap.NetworkMap) {
		mu.Lock()
		defer mu.Unlock()
		dns = netstack.DNSMapFromNetworkMap(nm)
	})
	useNetstackForIP := func(ip netaddr.IP) bool {
		// TODO(bradfitz): this isn't exactly right.
		// We should also support subnets when the
		// prefs are configured as such.
		return tsaddr.IsTailscaleIP(ip)
	}
	srv.Dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		ipp, err := dns.Resolve(ctx, addr)
		if err != nil {
			return nil, err
		}
		if ns != nil && useNetstackForIP(ipp.IP()) {
			return ns.DialContextTCP(ctx, addr)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, ipp.String())
	}
	return srv
}

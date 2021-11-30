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
	d := &dialer{ns: ns, eng: e}
	e.AddNetworkMapCallback(d.onNewNetmap)
	return &socks5.Server{
		Logf:   logf,
		Dialer: d.DialContext,
	}
}

// dialer is the Tailscale SOCKS5 dialer.
type dialer struct {
	ns  *netstack.Impl
	eng wgengine.Engine

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
	if d.ns == nil || !d.ns.ProcessLocalIPs {
		// If netstack isn't used at all (nil), then obviously don't use it.
		//
		// But the ProcessLocalIPs check is more subtle: it really means
		// whether we should use netstack for incoming traffic to ourselves.
		// It's only ever true if we're running in full netstack mode (no TUN),
		// so we can also use it as a proxy here for whether TUN is available.
		// If it's false, there's tun and OS routes to things we need,
		// so we don't want to dial with netstack.
		return false
	}
	// Otherwise, we're in netstack mode, so dial via netstack if there's
	// any peer handling that IP (including exit nodes).
	//
	// Otherwise assume it's something else (e.g. dialing
	// google.com:443 via SOCKS) that the caller can dial directly.
	_, ok := d.eng.PeerForIP(ip)
	return ok
}

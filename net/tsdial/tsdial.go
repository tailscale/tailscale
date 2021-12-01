// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tsdial provides a Dialer type that can dial out of tailscaled.
package tsdial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"inet.af/netaddr"
	"tailscale.com/net/netknob"
	"tailscale.com/wgengine/monitor"
)

// Dialer dials out of tailscaled, while taking care of details while
// handling the dozens of edge cases depending on the server mode
// (TUN, netstack), the OS network sandboxing style (macOS/iOS
// Extension, none), user-selected route acceptance prefs, etc.
type Dialer struct {
	// UseNetstackForIP if non-nil is whether NetstackDialTCP (if
	// it's non-nil) should be used to dial the provided IP.
	UseNetstackForIP func(netaddr.IP) bool

	// NetstackDialTCP dials the provided IPPort using netstack.
	// If nil, it's not used.
	NetstackDialTCP func(context.Context, netaddr.IPPort) (net.Conn, error)

	peerDialControlFuncAtomic atomic.Value // of func() func(network, address string, c syscall.RawConn) error

	peerClientOnce sync.Once
	peerClient     *http.Client

	peerDialerOnce sync.Once
	peerDialer     *net.Dialer

	mu      sync.Mutex
	dns     DNSMap
	tunName string // tun device name
	linkMon *monitor.Mon
}

// SetTUNName sets the name of the tun device in use ("tailscale0", "utun6",
// etc). This is needed on some platforms to set sockopts to bind
// to the same interface index.
func (d *Dialer) SetTUNName(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tunName = name
}

// TUNName returns the name of the tun device in use, if any.
// Example format ("tailscale0", "utun6").
func (d *Dialer) TUNName() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.tunName
}

func (d *Dialer) SetLinkMonitor(mon *monitor.Mon) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.linkMon = mon
}

func (d *Dialer) interfaceIndexLocked(ifName string) (index int, ok bool) {
	if d.linkMon == nil {
		return 0, false
	}
	st := d.linkMon.InterfaceState()
	iface, ok := st.Interface[ifName]
	if !ok {
		return 0, false
	}
	return iface.Index, true
}

// peerDialControlFunc is non-nil on platforms that require a way to
// bind to dial out to other peers.
var peerDialControlFunc func(*Dialer) func(network, address string, c syscall.RawConn) error

// PeerDialControlFunc returns a function
// that can assigned to net.Dialer.Control to set sockopts or whatnot
// to make a dial escape the current platform's network sandbox.
//
// On many platforms the returned func will be nil.
//
// Notably, this is non-nil on iOS and macOS when run as a Network or
// System Extension (the GUI variants).
func (d *Dialer) PeerDialControlFunc() func(network, address string, c syscall.RawConn) error {
	if peerDialControlFunc == nil {
		return nil
	}
	return peerDialControlFunc(d)
}

// SetDNSMap sets the current map of DNS names learned from the netmap.
func (d *Dialer) SetDNSMap(m DNSMap) {
	// TODO(bradfitz): update this to be aware of DNSConfig
	// ExtraNames and CertDomains.
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dns = m
}

func (d *Dialer) resolve(ctx context.Context, addr string) (netaddr.IPPort, error) {
	d.mu.Lock()
	dns := d.dns
	d.mu.Unlock()
	return dns.Resolve(ctx, addr)
}

// UserDial connects to the provided network address as if a user were initiating the dial.
// (e.g. from a SOCKS or HTTP outbound proxy)
func (d *Dialer) UserDial(ctx context.Context, network, addr string) (net.Conn, error) {
	ipp, err := d.resolve(ctx, addr)
	if err != nil {
		return nil, err
	}
	if d.UseNetstackForIP != nil && d.UseNetstackForIP(ipp.IP()) {
		if d.NetstackDialTCP == nil {
			return nil, errors.New("Dialer not initialized correctly")
		}
		return d.NetstackDialTCP(ctx, ipp)
	}
	// TODO(bradfitz): netns, etc
	var stdDialer net.Dialer
	return stdDialer.DialContext(ctx, network, ipp.String())
}

// dialPeerAPI connects to a Tailscale peer's peerapi over TCP.
//
// network must a "tcp" type, and addr must be an ip:port. Name resolution
// is not supported.
func (d *Dialer) dialPeerAPI(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, fmt.Errorf("peerAPI dial requires tcp; %q not supported", network)
	}
	ipp, err := netaddr.ParseIPPort(addr)
	if err != nil {
		return nil, fmt.Errorf("peerAPI dial requires ip:port, not name resolution: %w", err)
	}
	if d.UseNetstackForIP != nil && d.UseNetstackForIP(ipp.IP()) {
		if d.NetstackDialTCP == nil {
			return nil, errors.New("Dialer not initialized correctly")
		}
		return d.NetstackDialTCP(ctx, ipp)
	}
	return d.getPeerDialer().DialContext(ctx, network, addr)
}

// getPeerDialer returns the *net.Dialer to use to dial peers to use
// peer API.
//
// This is not used in netstack mode.
//
// The primary function of this is to work on macOS & iOS's in the
// Network/System Extension so it can mark the dialer as staying
// withing the network namespace/sandbox.
func (d *Dialer) getPeerDialer() *net.Dialer {
	d.peerDialerOnce.Do(func() {
		d.peerDialer = &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: netknob.PlatformTCPKeepAlive(),
			Control:   d.PeerDialControlFunc(),
		}
	})
	return d.peerDialer
}

// PeerAPIHTTPClient returns an HTTP Client to call peers' peerapi
// endpoints.                                                                                                                                                                                                                      //
// The returned Client must not be mutated; it's owned by the Dialer
// and shared by callers.
func (d *Dialer) PeerAPIHTTPClient() *http.Client {
	d.peerClientOnce.Do(func() {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Dial = nil
		t.DialContext = d.dialPeerAPI
		d.peerClient = &http.Client{Transport: t}
	})
	return d.peerClient
}

// PeerAPITransport returns a Transport to call peers' peerapi
// endpoints.
//
// The returned value must not be mutated; it's owned by the Dialer
// and shared by callers.
func (d *Dialer) PeerAPITransport() *http.Transport {
	return d.PeerAPIHTTPClient().Transport.(*http.Transport)
}

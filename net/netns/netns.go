// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netns contains the common code for using the Go net package
// in a logical "network namespace" to avoid routing loops where
// Tailscale-created packets would otherwise loop back through
// Tailscale routes.
//
// Despite the name netns, the exact mechanism used differs by
// operating system, and perhaps even by version of the OS.
//
// The netns package also handles connecting via SOCKS proxies when
// configured by the environment.
package netns

import (
	"context"
	"net"

	"inet.af/netaddr"
	"tailscale.com/syncs"
)

var disabled syncs.AtomicBool

// SetEnabled enables or disables netns for the process.
// It defaults to being enabled.
func SetEnabled(on bool) {
	disabled.Set(!on)
}

// Listener returns a new net.Listener with its Control hook func
// initialized as necessary to run in logical network namespace that
// doesn't route back into Tailscale.
func Listener() *net.ListenConfig {
	if disabled.Get() {
		return new(net.ListenConfig)
	}
	return &net.ListenConfig{Control: control}
}

// NewDialer returns a new Dialer using a net.Dialer with its Control
// hook func initialized as necessary to run in a logical network
// namespace that doesn't route back into Tailscale. It also handles
// using a SOCKS if configured in the environment with ALL_PROXY.
func NewDialer() Dialer {
	return FromDialer(new(net.Dialer))
}

// FromDialer returns sets d.Control as necessary to run in a logical
// network namespace that doesn't route back into Tailscale. It also
// handles using a SOCKS if configured in the environment with
// ALL_PROXY.
func FromDialer(d *net.Dialer) Dialer {
	if disabled.Get() {
		return d
	}
	d.Control = control
	if wrapDialer != nil {
		return wrapDialer(d)
	}
	return d
}

// IsSOCKSDialer reports whether d is SOCKS-proxying dialer as returned by
// NewDialer or FromDialer.
func IsSOCKSDialer(d Dialer) bool {
	if d == nil {
		return false
	}
	_, ok := d.(*net.Dialer)
	return !ok
}

// wrapDialer, if non-nil, specifies a function to wrap a dialer in a
// SOCKS-using dialer. It's set conditionally by socks.go.
var wrapDialer func(Dialer) Dialer

// Dialer is the interface for a dialer that can dial with or without a context.
// It's the type implemented both by net.Dialer and the Go SOCKS dialer.
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func isLocalhost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// error means the string didn't contain a port number, so use the string directly
		host = addr
	}

	// localhost6 == RedHat /etc/hosts for ::1, ip6-loopback & ip6-localhost == Debian /etc/hosts for ::1
	if host == "localhost" || host == "localhost6" || host == "ip6-loopback" || host == "ip6-localhost" {
		return true
	}

	ip, _ := netaddr.ParseIP(host)
	return ip.IsLoopback()
}

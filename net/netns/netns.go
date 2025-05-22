// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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
	"net/netip"
	"sync/atomic"

	"tailscale.com/net/netknob"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

var disabled atomic.Bool

// SetEnabled enables or disables netns for the process.
// It defaults to being enabled.
func SetEnabled(on bool) {
	disabled.Store(!on)
}

var bindToInterfaceByRoute atomic.Bool

// SetBindToInterfaceByRoute enables or disables whether we use the system's
// route information to bind to a particular interface. It is the same as
// setting the TS_BIND_TO_INTERFACE_BY_ROUTE.
//
// Currently, this only changes the behaviour on macOS and Windows.
func SetBindToInterfaceByRoute(v bool) {
	bindToInterfaceByRoute.Store(v)
}

var disableBindConnToInterface atomic.Bool

// SetDisableBindConnToInterface disables the (normal) behavior of binding
// connections to the default network interface.
//
// Currently, this only has an effect on Darwin.
func SetDisableBindConnToInterface(v bool) {
	disableBindConnToInterface.Store(v)
}

// Listener returns a new net.Listener with its Control hook func
// initialized as necessary to run in logical network namespace that
// doesn't route back into Tailscale.
func Listener(logf logger.Logf, netMon *netmon.Monitor) ListenerInterface {
	if netMon == nil {
		panic("netns.Listener called with nil netMon")
	}
	if disabled.Load() {
		return new(net.ListenConfig)
	}
	l := &net.ListenConfig{Control: control(logf, netMon)}
	if wrapListener != nil {
		return wrapListener(l)
	}
	return l
}

// NewDialer returns a new Dialer using a net.Dialer with its Control
// hook func initialized as necessary to run in a logical network
// namespace that doesn't route back into Tailscale. It also handles
// using a SOCKS if configured in the environment with ALL_PROXY.
func NewDialer(logf logger.Logf, netMon *netmon.Monitor) Dialer {
	if netMon == nil {
		panic("netns.NewDialer called with nil netMon")
	}
	return FromDialer(logf, netMon, &net.Dialer{
		KeepAlive: netknob.PlatformTCPKeepAlive(),
	})
}

// FromDialer returns sets d.Control as necessary to run in a logical
// network namespace that doesn't route back into Tailscale. It also
// handles using a SOCKS if configured in the environment with
// ALL_PROXY.
func FromDialer(logf logger.Logf, netMon *netmon.Monitor, d *net.Dialer) Dialer {
	if netMon == nil {
		panic("netns.FromDialer called with nil netMon")
	}
	if disabled.Load() {
		return d
	}
	d.Control = control(logf, netMon)
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

// wrapDialer, if non-nil, specifies a function to wrap a dialer.
// It's set conditionally by socks.go or SetWrapDialer.
var wrapDialer func(Dialer) Dialer

// SetWrapDialer specifies a function to wrap a dialer
func SetWrapDialer(f func(Dialer) Dialer) { wrapDialer = f }

// Dialer is the interface for a dialer that can dial with or without a context.
// It's the type implemented both by net.Dialer and the Go SOCKS dialer.
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// wrapListener, if non-nil, specifies a function to wrap a listener
var wrapListener func(ListenerInterface) ListenerInterface

// SetWrapListener specifies a function to wrap a listener
func SetWrapListener(f func(ListenerInterface) ListenerInterface) { wrapListener = f }

// ListenerInterface is the interface for a listener that can listen
// net.Listener and net.PacketConn
type ListenerInterface interface {
	Listen(ctx context.Context, network, address string) (net.Listener, error)
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
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

	ip, _ := netip.ParseAddr(host)
	return ip.IsLoopback()
}

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
	"runtime"
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
func SetBindToInterfaceByRoute(logf logger.Logf, v bool) {
	if bindToInterfaceByRoute.Swap(v) != v {
		logf("netns: bindToInterfaceByRoute changed to %v", v)
	}
}

var disableBindConnToInterface atomic.Bool

// SetDisableBindConnToInterface disables the (normal) behavior of binding
// connections to the default network interface on Darwin nodes.
//
// Unless you intended to disable this for tailscaled on macos (which is likely
// to break things), you probably wanted to set
// SetDisableBindConnToInterfaceAppleExt which will disable explicit interface
// binding only when tailscaled is running inside a network extension process.
func SetDisableBindConnToInterface(logf logger.Logf, v bool) {
	if disableBindConnToInterface.Swap(v) != v {
		logf("netns: disableBindConnToInterface changed to %v", v)
	}
}

var disableBindConnToInterfaceAppleExt atomic.Bool

// SetDisableBindConnToInterfaceAppleExt disables the (normal) behavior of binding
// connections to the default network interface but only on Apple clients where
// tailscaled is running inside a network extension.
func SetDisableBindConnToInterfaceAppleExt(logf logger.Logf, v bool) {
	if runtime.GOOS == "darwin" && disableBindConnToInterfaceAppleExt.Swap(v) != v {
		logf("netns: disableBindConnToInterfaceAppleExt changed to %v", v)
	}
}

// Listener returns a new net.Listener with its Control hook func
// initialized as necessary to run in logical network namespace that
// doesn't route back into Tailscale.
func Listener(logf logger.Logf, netMon *netmon.Monitor) *net.ListenConfig {
	if netMon == nil {
		panic("netns.Listener called with nil netMon")
	}
	if disabled.Load() {
		return new(net.ListenConfig)
	}
	return &net.ListenConfig{Control: control(logf, netMon)}
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

	ip, _ := netip.ParseAddr(host)
	return ip.IsLoopback()
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package netstack

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
)

// canBindLoopbackBeforeConnect reports whether this platform supports
// binding a not-yet-connected dial socket to learn its local address before
// the TCP handshake completes.
const canBindLoopbackBeforeConnect = true

// bindLoopbackFD binds the socket behind fd to (ip, port 0), where ip must
// be a loopback address, and returns the socket's kernel-assigned local
// address. Binding before connect lets the caller own and register the
// ephemeral port before the peer can observe the connection; see issue
// #1616.
func bindLoopbackFD(fd uintptr, ip netip.Addr) (netip.AddrPort, error) {
	var sa windows.Sockaddr
	switch {
	case ip.Is4():
		sa = &windows.SockaddrInet4{Addr: ip.As4()}
	case ip.Is6():
		sa = &windows.SockaddrInet6{Addr: ip.As16()}
	default:
		return netip.AddrPort{}, fmt.Errorf("bindLoopbackFD: %v is not an IP address", ip)
	}
	if err := windows.Bind(windows.Handle(fd), sa); err != nil {
		return netip.AddrPort{}, fmt.Errorf("bindLoopbackFD: bind: %w", err)
	}
	bound, err := windows.Getsockname(windows.Handle(fd))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bindLoopbackFD: getsockname: %w", err)
	}
	switch sa := bound.(type) {
	case *windows.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port)), nil
	case *windows.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), uint16(sa.Port)), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("bindLoopbackFD: unexpected bound address type %T", bound)
	}
}

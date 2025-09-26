// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netstack

package ipnlocal

import (
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"tailscale.com/types/ptr"
)

// TCPHandlerForDst returns a TCP handler for connections to dst, or nil if
// no handler is needed. It also returns a list of TCP socket options to
// apply to the socket before calling the handler.
// TCPHandlerForDst is called both for connections to our node's local IP
// as well as to the service IP (quad 100).
func (b *LocalBackend) TCPHandlerForDst(src, dst netip.AddrPort) (handler func(c net.Conn) error, opts []tcpip.SettableSocketOption) {
	// First handle internal connections to the service IP
	hittingServiceIP := dst.Addr() == magicDNSIP || dst.Addr() == magicDNSIPv6
	if hittingServiceIP {
		switch dst.Port() {
		case 80:
			// TODO(mpminardi): do we want to show an error message if the web client
			// has been disabled instead of the more "basic" web UI?
			if b.ShouldRunWebClient() {
				return b.handleWebClientConn, opts
			}
			return b.HandleQuad100Port80Conn, opts
		case DriveLocalPort:
			return b.handleDriveConn, opts
		}
	}

	if f, ok := hookServeTCPHandlerForVIPService.GetOk(); ok {
		if handler := f(b, dst, src); handler != nil {
			return handler, opts
		}
	}
	// Then handle external connections to the local IP.
	if !b.isLocalIP(dst.Addr()) {
		return nil, nil
	}
	if dst.Port() == 22 && b.ShouldRunSSH() {
		// Use a higher keepalive idle time for SSH connections, as they are
		// typically long lived and idle connections are more likely to be
		// intentional. Ideally we would turn this off entirely, but we can't
		// tell the difference between a long lived connection that is idle
		// vs a connection that is dead because the peer has gone away.
		// We pick 72h as that is typically sufficient for a long weekend.
		opts = append(opts, ptr.To(tcpip.KeepaliveIdleOption(72*time.Hour)))
		return b.handleSSHConn, opts
	}
	// TODO(will,sonia): allow customizing web client port ?
	if dst.Port() == webClientPort && b.ShouldExposeRemoteWebClient() {
		return b.handleWebClientConn, opts
	}
	if port, ok := b.GetPeerAPIPort(dst.Addr()); ok && dst.Port() == port {
		return func(c net.Conn) error {
			b.handlePeerAPIConn(src, dst, c)
			return nil
		}, opts
	}
	if f, ok := hookTCPHandlerForServe.GetOk(); ok {
		if handler := f(b, dst.Port(), src, nil); handler != nil {
			return handler, opts
		}
	}
	return nil, nil
}

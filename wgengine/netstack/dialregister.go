// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"tailscale.com/proxymap"
)

// dialTCPRegisterLocal dials dst, which must be a loopback address, and
// returns the established connection along with its local address. Unlike a
// plain net.Dialer dial, the proxymap registration for the connection's
// local address (mapped to clientIP) is created before the TCP handshake
// completes: the socket is bound to an ephemeral loopback port up front,
// that address is registered, and only then is the connect issued.
//
// A loopback backend learns about the proxied connection as soon as the
// kernel completes the handshake, and localhost servers (peerapi, serve)
// can immediately WhoIs the connection's source address against tailscaled.
// Registering only after DialContext returns loses that race (issue #1616):
// the kernel only assigns an ephemeral port at connect time, so beforehand
// there is nothing to register. Owning the port in the kernel first and
// registering it before dialing closes the window without resorting to the
// port-guessing the issue discussion rules out.
//
// The caller owns unregistering the returned address once the connection is
// done. On platforms where bindLoopbackFD is unavailable, this falls back
// to registering after the dial completes, the pre-#1616 behavior.
func dialTCPRegisterLocal(ctx context.Context, dst netip.AddrPort, pm *proxymap.Mapper, clientIP netip.Addr) (net.Conn, netip.AddrPort, error) {
	if !dst.Addr().IsLoopback() {
		return nil, netip.AddrPort{}, fmt.Errorf("dialTCPRegisterLocal: %v is not a loopback address", dst)
	}
	if !canBindLoopbackBeforeConnect {
		return dialTCPThenRegister(ctx, dst, pm, clientIP)
	}

	var (
		// Guarded for the theoretical case of concurrent dial attempts
		// (Happy Eyeballs); an IP-literal loopback dial makes exactly one
		// attempt on the calling goroutine, but the ControlContext contract
		// does not promise that in general.
		mu         sync.Mutex
		registered []netip.AddrPort
	)
	d := net.Dialer{
		ControlContext: func(_ context.Context, network, address string, c syscall.RawConn) error {
			var berr error
			err := c.Control(func(fd uintptr) {
				var ap netip.AddrPort
				ap, berr = bindLoopbackFD(fd, dst.Addr())
				if berr != nil {
					return
				}
				if err := pm.RegisterIPPortIdentity("tcp", ap, clientIP); err != nil {
					berr = err
					return
				}
				mu.Lock()
				registered = append(registered, ap)
				mu.Unlock()
			})
			if err != nil {
				return err
			}
			return berr
		},
	}
	conn, err := d.DialContext(ctx, "tcp", dst.String())

	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		for _, ap := range registered {
			pm.UnregisterIPPortIdentity("tcp", ap)
		}
		return nil, netip.AddrPort{}, err
	}

	ta, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		conn.Close()
		for _, ap := range registered {
			pm.UnregisterIPPortIdentity("tcp", ap)
		}
		return nil, netip.AddrPort{}, fmt.Errorf("dialTCPRegisterLocal: unexpected local address type %T", conn.LocalAddr())
	}
	local := netip.AddrPortFrom(ta.AddrPort().Addr().Unmap(), ta.AddrPort().Port())

	// The connected socket's address is the one that must stay registered;
	// drop any stale registrations from earlier failed attempts.
	found := false
	for _, ap := range registered {
		if ap == local {
			found = true
		} else {
			pm.UnregisterIPPortIdentity("tcp", ap)
		}
	}
	if !found {
		conn.Close()
		return nil, netip.AddrPort{}, fmt.Errorf("dialTCPRegisterLocal: connected address %v was never registered", local)
	}
	return conn, local, nil
}

// dialTCPThenRegister dials dst with a plain net.Dialer and registers the
// connection's local address in pm after the dial completes. It is the
// fallback for platforms where bindLoopbackFD is unavailable, and matches
// how the registration was done unconditionally before issue #1616 was
// fixed.
func dialTCPThenRegister(ctx context.Context, dst netip.AddrPort, pm *proxymap.Mapper, clientIP netip.Addr) (net.Conn, netip.AddrPort, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	ta, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		conn.Close()
		return nil, netip.AddrPort{}, fmt.Errorf("dialTCPThenRegister: unexpected local address type %T", conn.LocalAddr())
	}
	local := netip.AddrPortFrom(ta.AddrPort().Addr().Unmap(), ta.AddrPort().Port())
	if err := pm.RegisterIPPortIdentity("tcp", local, clientIP); err != nil {
		conn.Close()
		return nil, netip.AddrPort{}, err
	}
	return conn, local, nil
}

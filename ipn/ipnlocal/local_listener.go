// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"tailscale.com/net/netmon"
	"tailscale.com/syncs"
	"tailscale.com/types/logger"
	"tailscale.com/util/backoff"
	"tailscale.com/version"
)

// localListener is the state of host-level net.Listen for a specific (Tailscale IP, port)
// combination. If there are two TailscaleIPs (v4 and v6) and three ports being served,
// then there will be six of these active and looping in their Run method.
//
// This is not used in userspace-networking mode.
//
// localListener is used by tailscale serve (TCP only), the built-in web client and Taildrive.
// Most serve traffic and peer traffic for the web client are intercepted by netstack.
// This listener exists purely for connections from the machine itself, as that goes via the kernel,
// so we need to be in the kernel's listening/routing tables.
type localListener struct {
	b      *LocalBackend
	ap     netip.AddrPort
	ctx    context.Context    // valid while listener is desired
	cancel context.CancelFunc // for ctx, to close listener
	logf   logger.Logf
	bo     *backoff.Backoff // for retrying failed Listen calls

	handler       func(net.Conn) error            // handler for inbound connections
	closeListener syncs.AtomicValue[func() error] // Listener's Close method, if any

	// allowAllInterfaces, if set, stops the listener from being bound to the
	// Tailscale interface, so it answers traffic arriving on any interface.
	// Only serve listeners set it, and only when serveAllowAllInterfaces is
	// set; the web client listener always stays bound.
	allowAllInterfaces bool
}

// Close cancels the context and closes the listener, if any.
func (s *localListener) Close() error {
	s.cancel()
	if close, ok := s.closeListener.LoadOk(); ok {
		s.closeListener.Store(nil)
		close()
	}
	return nil
}

// Run starts a net.Listen for the localListener's address and port.
// If unable to listen, it retries with exponential backoff.
// Listen is retried until the context is canceled.
func (s *localListener) Run() {
	for {
		ip := s.ap.Addr()
		ipStr := ip.String()

		var lc net.ListenConfig
		if initListenConfig != nil && !s.allowAllInterfaces {
			ifIndex, err := netmon.TailscaleInterfaceIndex()
			if err != nil {
				s.logf("localListener failed to get Tailscale interface index %v, backing off: %v", s.ap, err)
				s.bo.BackOff(s.ctx, err)
				continue
			}

			// On macOS, this sets the lc.Control hook to
			// setsockopt the interface index to bind to. This is
			// required by the network sandbox which will not automatically
			// bind to the tailscale interface to prevent routing loops.
			// Explicit binding allows us to bypass that restriction.
			if err := initListenConfig(&lc, ip, ifIndex); err != nil {
				s.logf("localListener failed to init listen config %v, backing off: %v", s.ap, err)
				s.bo.BackOff(s.ctx, err)
				continue
			}

			// On macOS (AppStore or macsys) and if we're binding to a privileged port,
			if version.IsSandboxedMacOS() && s.ap.Port() < 1024 {
				// On macOS, we need to bind to ""/all-interfaces due to
				// the network sandbox. Ideally we would only bind to the
				// Tailscale interface, but macOS errors out if we try to
				// to listen on privileged ports binding only to a specific
				// interface. (#6364)
				ipStr = ""
			}
		}

		tcp4or6 := "tcp4"
		if ip.Is6() {
			tcp4or6 = "tcp6"
		}

		// while we were backing off and trying again, the context got canceled
		// so don't bind, just return, because otherwise there will be no way
		// to close this listener
		if s.ctx.Err() != nil {
			s.logf("localListener context closed before binding")
			return
		}

		ln, err := lc.Listen(s.ctx, tcp4or6, net.JoinHostPort(ipStr, fmt.Sprint(s.ap.Port())))
		if err != nil {
			if s.shouldWarnAboutListenError(err) {
				s.logf("localListener failed to listen on %v, backing off: %v", s.ap, err)
			}
			s.bo.BackOff(s.ctx, err)
			continue
		}
		s.closeListener.Store(ln.Close)

		s.logf("listening on %v", s.ap)
		// handleListenersAccept always returns a non-nil error.
		err = s.handleListenersAccept(ln)
		if s.ctx.Err() != nil {
			// context canceled, we're done
			return
		}
		s.logf("localListener accept error, retrying: %v", err)
	}
}

func (s *localListener) shouldWarnAboutListenError(err error) bool {
	if !s.b.sys.NetMon.Get().InterfaceState().HasIP(s.ap.Addr()) {
		// Machine likely doesn't have IPv6 enabled (or the IP is still being
		// assigned). No need to warn. Notably, WSL2 (Issue 6303).
		return false
	}
	// TODO(bradfitz): check errors.Is(err, syscall.EADDRNOTAVAIL) etc? Let's
	// see what happens in practice.
	return true
}

// handleListenersAccept accepts connections for the Listener. It calls the
// handler in a new goroutine for each accepted connection. This is used to
// handle local "tailscale serve" and web client traffic originating from the
// machine itself.
func (s *localListener) handleListenersAccept(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handler(conn)
	}
}

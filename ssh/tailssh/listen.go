// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	gliderssh "github.com/tailscale/gliderssh"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/types/logger"
)

func init() {
	ipnlocal.HookListenSSH.Set(listenSSH)
}

// listenSSH wraps rawLn with an SSH server that resolves Tailscale peer
// identity for each connection. The returned listener's Accept yields
// *Session values (as net.Conn).
func listenSSH(rawLn net.Listener, lb *ipnlocal.LocalBackend, logf logger.Logf) (net.Listener, error) {
	hostKeys, err := getHostKeys(lb.TailscaleVarRoot(), logf)
	if err != nil {
		return nil, err
	}
	signers := make([]gliderssh.Signer, len(hostKeys))
	for i, k := range hostKeys {
		signers[i] = k
	}

	sl := &sshListener{
		rawLn:    rawLn,
		sessions: make(chan net.Conn, 16),
		done:     make(chan struct{}),
	}

	sshSrv := &gliderssh.Server{
		HostSigners: signers,
		Handler: func(sess gliderssh.Session) {
			srcAddr := sess.RemoteAddr().String()
			ipp, err := netip.ParseAddrPort(srcAddr)
			if err != nil {
				logf("listenSSH: bad remote addr %q: %v", srcAddr, err)
				sess.Exit(1)
				return
			}
			node, userProfile, ok := lb.WhoIs("tcp", ipp)
			if !ok {
				logf("listenSSH: WhoIs failed for %v", srcAddr)
				sess.Exit(1)
				return
			}

			done := make(chan struct{})
			s := newSession(sess, peerIdentity{
				Node:        node,
				UserProfile: userProfile,
			}, done)

			// Send the session to the listener. If the listener is
			// closed, drop the session.
			select {
			case sl.sessions <- s:
			case <-sl.done:
				sess.Exit(1)
				return
			}

			// Block until the consumer is done with the session.
			select {
			case <-done:
			case <-sess.Context().Done():
			case <-sl.done:
			}
		},
	}

	go func() {
		if err := sshSrv.Serve(rawLn); err != nil {
			// Serve returns when the listener is closed. Only log
			// unexpected errors.
			select {
			case <-sl.done:
			default:
				logf("listenSSH: Serve error: %v", err)
			}
		}
		sl.Close()
	}()

	return sl, nil
}

// sshListener is a net.Listener that yields *Session values from its Accept
// method. It wraps a raw TCP listener with an SSH server.
type sshListener struct {
	rawLn     net.Listener
	sessions  chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

// Accept returns the next SSH session as a net.Conn. The returned value can
// be type-asserted to *Session.
func (sl *sshListener) Accept() (net.Conn, error) {
	select {
	case s, ok := <-sl.sessions:
		if !ok {
			return nil, errors.New("listener closed")
		}
		return s, nil
	case <-sl.done:
		return nil, errors.New("listener closed")
	}
}

// Close closes the underlying raw listener and signals all pending sessions
// to terminate.
func (sl *sshListener) Close() error {
	var err error
	sl.closeOnce.Do(func() {
		close(sl.done)
		err = sl.rawLn.Close()
	})
	return err
}

// Addr returns the address of the underlying raw listener.
func (sl *sshListener) Addr() net.Addr {
	return sl.rawLn.Addr()
}

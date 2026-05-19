// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet2

import (
	"net"
)

// listener is the [net.Listener] implementation returned by
// [Server.Listen] once the daemon-backed listener is wired up.
//
// All methods currently panic. The implementation will be filled in by a
// later agent; the type exists today so the package compiles and so
// callers can perform interface type assertions in tests.
type listener struct {
	s    *Server
	addr addr
}

// Compile-time check that *listener satisfies net.Listener.
var _ net.Listener = (*listener)(nil)

// Accept waits for and returns the next connection to the listener.
func (l *listener) Accept() (net.Conn, error) {
	panic("tsnet2: listener.Accept not implemented")
}

// Close closes the listener. Any blocked Accept operations will be
// unblocked and return errors.
func (l *listener) Close() error {
	panic("tsnet2: listener.Close not implemented")
}

// Addr returns the listener's network address.
func (l *listener) Addr() net.Addr {
	return l.addr
}

// Server returns the tsnet2 Server associated with the listener. It
// matches the equivalent method on tsnet's listener so callers that
// reach in via type-assertion can still do so.
func (l *listener) Server() *Server { return l.s }

// addr implements [net.Addr] for tsnet2 listeners and connections.
type addr struct {
	network string
	addr    string
}

func (a addr) Network() string { return a.network }
func (a addr) String() string  { return a.addr }

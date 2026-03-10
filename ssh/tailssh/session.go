// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"sync"
	"time"

	gliderssh "github.com/tailscale/gliderssh"
	"tailscale.com/tailcfg"
)

var errNoDeadline = errors.New("tailssh.Session: deadlines not supported")

// Signal represents an SSH signal (e.g. "INT", "TERM").
type Signal = gliderssh.Signal

// Pty represents a PTY request and configuration.
type Pty struct {
	// Term is the TERM environment variable value.
	Term string

	// Window is the initial window size.
	Window Window

	// Modes are the RFC 4254 terminal modes as opcode/value pairs.
	Modes map[uint8]uint32
}

// Window represents the size of a PTY window.
type Window struct {
	Width        int // columns
	Height       int // rows
	WidthPixels  int // width in pixels
	HeightPixels int // height in pixels
}

// peerIdentity contains the Tailscale identity of the connecting SSH peer.
type peerIdentity struct {
	Node        tailcfg.NodeView // node connecting
	UserProfile tailcfg.UserProfile
}

// Session wraps a gliderlabs gliderssh.Session with Tailscale peer identity
// information. It implements net.Conn so callers that only need Read/Write/Close
// can use it directly. Callers that need SSH-specific functionality can
// type-assert from the net.Conn returned by the listener's Accept.
type Session struct {
	// sess is the underlying gliderlabs SSH session.
	sess gliderssh.Session

	// peer is the Tailscale identity of the remote peer.
	peer peerIdentity

	// done is closed when the session handler should return,
	// unblocking the gliderlabs handler goroutine.
	doneOnce sync.Once // guards close(done)
	done     chan struct{}
}

// newSession creates a new Session wrapping the given gliderlabs session and
// peer identity. The done channel is closed by the session consumer to signal
// that the handler goroutine may return.
func newSession(sess gliderssh.Session, peer peerIdentity, done chan struct{}) *Session {
	return &Session{
		sess: sess,
		peer: peer,
		done: done,
	}
}

// Read reads from the SSH channel (stdin from the client).
func (s *Session) Read(p []byte) (int, error) {
	return s.sess.Read(p)
}

// Write writes to the SSH channel (stdout to the client).
func (s *Session) Write(p []byte) (int, error) {
	return s.sess.Write(p)
}

// Close signals the session handler to return and closes the underlying channel.
func (s *Session) Close() error {
	s.doneOnce.Do(func() { close(s.done) })
	return nil
}

// RemoteAddr returns the net.Addr of the client side of the connection.
func (s *Session) RemoteAddr() net.Addr {
	return s.sess.RemoteAddr()
}

// LocalAddr returns the net.Addr of the server side of the connection.
func (s *Session) LocalAddr() net.Addr {
	return s.sess.LocalAddr()
}

// SetDeadline is not supported and returns an error.
func (s *Session) SetDeadline(t time.Time) error {
	return errNoDeadline
}

// SetReadDeadline is not supported and returns an error.
func (s *Session) SetReadDeadline(t time.Time) error {
	return errNoDeadline
}

// SetWriteDeadline is not supported and returns an error.
func (s *Session) SetWriteDeadline(t time.Time) error {
	return errNoDeadline
}

// User returns the SSH username.
func (s *Session) User() string {
	return s.sess.User()
}

// Peer returns the Tailscale identity of the remote node.
func (s *Session) Peer() tailcfg.NodeView { return s.peer.Node }

// UserProfile returns the Tailscale user profile of the remote node.
//
// For tagged nodes, this is same sort of UserProfile that is returned by the
// LocalAPI WhoIs API.
func (s *Session) UserProfile() tailcfg.UserProfile { return s.peer.UserProfile }

// Environ returns a copy of the environment variables set by the client.
func (s *Session) Environ() []string {
	return s.sess.Environ()
}

// RawCommand returns the exact command string provided by the client.
func (s *Session) RawCommand() string {
	return s.sess.RawCommand()
}

// Subsystem returns the subsystem requested by the client.
func (s *Session) Subsystem() string {
	return s.sess.Subsystem()
}

// Pty returns PTY information, a channel of window size changes, and whether a
// PTY was requested.
func (s *Session) Pty() (_ Pty, _ <-chan Window, ok bool) {
	gPty, gWinCh, ok := s.sess.Pty()
	if !ok {
		return Pty{}, nil, false
	}
	p := Pty{
		Term: gPty.Term,
		Window: Window{
			Width:        gPty.Window.Width,
			Height:       gPty.Window.Height,
			WidthPixels:  gPty.Window.WidthPixels,
			HeightPixels: gPty.Window.HeightPixels,
		},
	}
	if gPty.Modes != nil {
		p.Modes = make(map[uint8]uint32, len(gPty.Modes))
		maps.Copy(p.Modes, gPty.Modes)
	}

	// Convert the gliderlabs Window channel to our Window type.
	winCh := make(chan Window, 1)
	go func() {
		defer close(winCh)
		for gw := range gWinCh {
			winCh <- Window{
				Width:        gw.Width,
				Height:       gw.Height,
				WidthPixels:  gw.WidthPixels,
				HeightPixels: gw.HeightPixels,
			}
		}
	}()

	return p, winCh, true
}

// Signals registers a channel to receive signals from the client.
// Pass nil to unregister.
func (s *Session) Signals(c chan<- Signal) {
	s.sess.Signals(c)
}

// Exit sends an exit status to the client and closes the session.
func (s *Session) Exit(code int) error {
	err := s.sess.Exit(code)
	s.Close()
	return err
}

// Stderr returns an io.Writer for the SSH stderr channel.
func (s *Session) Stderr() io.Writer {
	return s.sess.Stderr()
}

// Context returns the session's context, which is canceled when the client
// disconnects.
func (s *Session) Context() context.Context {
	return s.sess.Context()
}

// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package safesocket creates either a Unix socket, if possible, or
// otherwise a localhost TCP connection.
package safesocket

import (
	"errors"
	"net"
	"runtime"
	"time"
)

// WindowsLocalPort is the default localhost TCP port
// used by safesocket on Windows.
const WindowsLocalPort = 41112

type closeable interface {
	CloseRead() error
	CloseWrite() error
}

// ConnCloseRead calls c's CloseRead method. c is expected to be
// either a UnixConn or TCPConn as returned from this package.
func ConnCloseRead(c net.Conn) error {
	return c.(closeable).CloseRead()
}

// ConnCloseWrite calls c's CloseWrite method. c is expected to be
// either a UnixConn or TCPConn as returned from this package.
func ConnCloseWrite(c net.Conn) error {
	return c.(closeable).CloseWrite()
}

var processStartTime = time.Now()
var tailscaledProcExists = func() bool { return false } // set by safesocket_ps.go

// tailscaledStillStarting reports whether tailscaled is probably
// still starting up. That is, it reports whether the caller should
// keep retrying to connect.
func tailscaledStillStarting() bool {
	d := time.Since(processStartTime)
	if d < 2*time.Second {
		// Without even checking the process table, assume
		// that for the first two seconds that tailscaled is
		// probably still starting.  That is, assume they're
		// running "tailscaled & tailscale up ...." and make
		// the tailscale client block for a bit for tailscaled
		// to start accepting on the socket.
		return true
	}
	if d > 5*time.Second {
		return false
	}
	return tailscaledProcExists()
}

// A ConnectionStrategy is a plan for how to connect to tailscaled or equivalent
// (e.g. IPNExtension on macOS).
//
// This is a struct because prior to Tailscale 1.34.0 it was more complicated
// and there were multiple protocols that could be used. See LocalClient's
// dialer for what happens in practice these days (2022-11-28).
//
// TODO(bradfitz): we can remove this struct now and revert this package closer
// to its original smaller API.
type ConnectionStrategy struct {
	path string // unix socket path
	port uint16 // TCP port

	// Longer term, a ConnectionStrategy should be an ordered list of things to attempt,
	// with just the information required to connection for each.
	//
	// We have at least these cases to consider (see issue 3530):
	//
	//   tailscale sandbox | tailscaled sandbox | OS      | connection
	//   ------------------|--------------------|---------|-----------
	//   no                | no                 | unix*   | unix socket *includes tailscaled on darwin
	//   no                | no                 | Windows | TCP/port
	//   no                | no                 | wasm    | memconn
	//   no                | Network Extension  | macOS   | TCP/port/token, port/token from lsof
	//   no                | System Extension   | macOS   | TCP/port/token, port/token from lsof
	//   yes               | Network Extension  | macOS   | TCP/port/token, port/token from readdir
	//   yes               | System Extension   | macOS   | TCP/port/token, port/token from readdir
	//
	// Note e.g. that port is only relevant as an input to Connect on Windows,
	// that path is not relevant to Windows, and that neither matters to wasm.
}

// DefaultConnectionStrategy returns a default connection strategy.
// The default strategy is to attempt to connect in as many ways as possible.
// It uses path as the unix socket path, when applicable,
// and defaults to WindowsLocalPort for the TCP port when applicable.
// It falls back to auto-discovery across sandbox boundaries on macOS.
// TODO: maybe take no arguments, since path is irrelevant on Windows? Discussion in PR 3499.
func DefaultConnectionStrategy(path string) *ConnectionStrategy {
	return &ConnectionStrategy{path: path, port: WindowsLocalPort}
}

// Connect connects to tailscaled using s
func Connect(s *ConnectionStrategy) (net.Conn, error) {
	for {
		c, err := connect(s)
		if err != nil && tailscaledStillStarting() {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		return c, err
	}
}

// Listen returns a listener either on Unix socket path (on Unix), or
// the localhost port (on Windows).
// If port is 0, the returned gotPort says which port was selected on Windows.
func Listen(path string, port uint16) (_ net.Listener, gotPort uint16, _ error) {
	return listen(path, port)
}

var (
	ErrTokenNotFound = errors.New("no token found")
	ErrNoTokenOnOS   = errors.New("no token on " + runtime.GOOS)
)

var localTCPPortAndToken func() (port int, token string, err error)

// LocalTCPPortAndToken returns the port number and auth token to connect to
// the local Tailscale daemon. It's currently only applicable on macOS
// when tailscaled is being run in the Mac Sandbox from the App Store version
// of Tailscale.
func LocalTCPPortAndToken() (port int, token string, err error) {
	if localTCPPortAndToken == nil {
		return 0, "", ErrNoTokenOnOS
	}
	return localTCPPortAndToken()
}

// PlatformUsesPeerCreds reports whether the current platform uses peer credentials
// to authenticate connections.
func PlatformUsesPeerCreds() bool { return GOOSUsesPeerCreds(runtime.GOOS) }

// GOOSUsesPeerCreds is like PlatformUsesPeerCreds but takes a
// runtime.GOOS value instead of using the current one.
func GOOSUsesPeerCreds(goos string) bool {
	switch goos {
	case "linux", "darwin", "freebsd":
		return true
	}
	return false
}

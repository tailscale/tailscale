// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package safesocket creates either a Unix socket, if possible, or
// otherwise a localhost TCP connection.
package safesocket

import (
	"errors"
	"net"
	"runtime"
	"time"
)

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

// Connect connects to tailscaled using a unix socket or named pipe.
func Connect(path string) (net.Conn, error) {
	for {
		c, err := connect(path)
		if err != nil && tailscaledStillStarting() {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		return c, err
	}
}

// Listen returns a listener either on Unix socket path (on Unix), or
// the NamedPipe path (on Windows).
func Listen(path string) (net.Listener, error) {
	return listen(path)
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

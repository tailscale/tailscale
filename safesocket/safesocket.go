// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows

// Package safesocket creates either a Unix socket, if possible, or
// otherwise a localhost TCP connection.
package safesocket

import (
	"net"
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

// Connect connects to either path (on Unix) or the provided localhost port (on Windows).
func Connect(path string, port uint16) (net.Conn, error) {
	return connect(path, port)
}

// Listen returns a listener either on Unix socket path (on Unix), or
// the localhost port (on Windows).
// If port is 0, the returned gotPort says which port was selected on Windows.
func Listen(path string, port uint16) (_ net.Listener, gotPort uint16, _ error) {
	return listen(path, port)
}

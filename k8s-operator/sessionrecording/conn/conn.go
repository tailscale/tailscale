// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package conn contains shared interface for the hijacked
// connection of a 'kubectl exec' session that is being recorded.
package conn

import "net"

type Conn interface {
	net.Conn
	// Fail can be called to set connection state to failed. This prevents
	// any so-far written bytes to be forwarded to the original destination
	// as the connection is closing.
	Fail()
}

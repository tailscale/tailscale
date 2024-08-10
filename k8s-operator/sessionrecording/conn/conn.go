// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package conn contains shared interface for the hijacked
// connection of a 'kubectl exec' session that is being recorded.
package conn

import "net"

type Conn interface {
	net.Conn
	// Fail can be called to set connection state to failed. By default any
	// bytes left over in write buffer are forwarded to the intended
	// destination when the connection is  being closed except for when the
	// connection state is failed- so set the state to failed when erroring
	// out and failure policy is to fail closed.
	Fail()
}

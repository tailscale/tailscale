// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlhttp

import (
	"tailscale.com/control/controlbase"
)

// ClientConn is a Tailscale control client as returned by the Dialer.
//
// It's effectively just a *controlbase.Conn (which it embeds) with
// optional metadata.
type ClientConn struct {
	// Conn is the noise connection.
	*controlbase.Conn
}

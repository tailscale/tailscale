// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

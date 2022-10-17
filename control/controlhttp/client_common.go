// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlhttp

import (
	"net/http"

	"tailscale.com/control/controlbase"
)

// ClientConn is a Tailscale control client as returned by the Dialer.
//
// It's effectively just a *controlbase.Conn (which it embeds) with
// optional metadata.
type ClientConn struct {
	// Conn is the noise connection.
	*controlbase.Conn

	// UntrustedUpgradeHeaders are the HTTP headers seen in the
	// 101 Switching Protocols upgrade response. They may be nil
	// or even might've been tampered with by a middlebox.
	// They should not be trusted.
	UntrustedUpgradeHeaders http.Header
}

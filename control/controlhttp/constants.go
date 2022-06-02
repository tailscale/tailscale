// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlhttp

const (
	// upgradeHeader is the value of the Upgrade HTTP header used to
	// indicate the Tailscale control protocol.
	upgradeHeaderValue = "tailscale-control-protocol"

	// handshakeHeaderName is the HTTP request header that can
	// optionally contain base64-encoded initial handshake
	// payload, to save an RTT.
	handshakeHeaderName = "X-Tailscale-Handshake"

	// serverUpgradePath is where the server-side HTTP handler to
	// to do the protocol switch is located.
	serverUpgradePath = "/ts2021"
)

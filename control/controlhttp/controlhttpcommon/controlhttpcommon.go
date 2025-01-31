// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package controlhttpcommon contains common constants for used
// by the controlhttp client and controlhttpserver packages.
package controlhttpcommon

// UpgradeHeader is the value of the Upgrade HTTP header used to
// indicate the Tailscale control protocol.
const UpgradeHeaderValue = "tailscale-control-protocol"

// handshakeHeaderName is the HTTP request header that can
// optionally contain base64-encoded initial handshake
// payload, to save an RTT.
const HandshakeHeaderName = "X-Tailscale-Handshake"

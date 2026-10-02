// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package controlhttpcommon contains common constants for used
// by the controlhttp client and controlhttpserver packages.
package controlhttpcommon

import (
	"encoding/base64"
	"strings"
)

// UpgradeHeader is the value of the Upgrade HTTP header used to
// indicate the Tailscale control protocol.
const UpgradeHeaderValue = "tailscale-control-protocol"

// handshakeHeaderName is the HTTP request header that can
// optionally contain base64-encoded initial handshake
// payload, to save an RTT.
const HandshakeHeaderName = "X-Tailscale-Handshake"

// ALPNHandshakePrefix is the prefix of a pseudo ALPN protocol name used to
// smuggle the client's Noise handshake initiation message inside a TLS
// ClientHello, saving a round trip versus sending an HTTP upgrade request
// inside the TLS session. The bytes following the prefix are the initiation
// message, encoded with base64.RawStdEncoding.
//
// A client offering such an entry also offers UpgradeHeaderValue as a regular
// ALPN protocol. A server that understands the smuggled handshake negotiates
// UpgradeHeaderValue, after which the TLS stream carries the Noise protocol
// directly (no HTTP layer), starting with the server's handshake response.
// Servers that don't understand it negotiate another protocol (or none), and
// the client falls back to the HTTP upgrade path over the same connection.
//
// The Noise initiation message is not secret; it's sent in cleartext HTTP
// headers on the port 80 dial path already, so exposing it in the ClientHello
// reveals nothing new.
const ALPNHandshakePrefix = "x-ts-handshake."

// EncodeALPNHandshake encodes init as an ALPN pseudo protocol name.
//
// The result must not exceed 255 bytes, the maximum length of an ALPN
// protocol name. The 101-byte ts2021 initiation message encodes to 150
// bytes, comfortably under the limit.
func EncodeALPNHandshake(init []byte) string {
	return ALPNHandshakePrefix + base64.RawStdEncoding.EncodeToString(init)
}

// DecodeALPNHandshake returns the Noise handshake initiation message
// smuggled in the provided ALPN protocol names, if any.
func DecodeALPNHandshake(protos []string) (init []byte, ok bool) {
	for _, p := range protos {
		b64, found := strings.CutPrefix(p, ALPNHandshakePrefix)
		if !found {
			continue
		}
		init, err := base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, false
		}
		return init, true
	}
	return nil, false
}

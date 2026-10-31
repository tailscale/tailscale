// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"

	"tailscale.com/types/key"
)

// tokenSecretLen is the length in bytes of the connector's token secret. It is
// the recommended key size for HMAC-SHA-256, which is used to mint and verify
// destination IP tokens.
const tokenSecretLen = 32

// tokenVersion1 is the version byte of the first token format.
const tokenVersion1 = 1

// tokenMACLen is the number of bytes of HMAC-SHA-256 output kept in a token. The
// full 32-byte MAC is truncated to save bytes on the wire.
const tokenMACLen = 16

// newTokenSecret returns a fresh random token secret.
func newTokenSecret() [tokenSecretLen]byte {
	var secret [tokenSecretLen]byte
	rand.Read(secret[:])
	return secret
}

// mintToken returns an opaque token authenticating that this connector served
// dst in a DNS answer for app to peer. The client stores it and echoes it back
// in a later TransitIPRequest, which this connector verifies by recomputing the
// MAC over the same inputs.
func (c *connector) mintToken(app string, dst netip.Addr, peer key.NodePublic) ([]byte, error) {
	if len(app) > math.MaxUint16 {
		return nil, fmt.Errorf("conn25: app name too long to mint token: %d bytes", len(app))
	}

	c.mu.Lock()
	secret := c.tokenSecret
	c.mu.Unlock()

	token := make([]byte, 0, 1+tokenMACLen)
	token = append(token, tokenVersion1)
	token = append(token, tokenMAC(secret, app, dst, peer)...)
	return token, nil
}

// verifyToken reports whether token is a valid [tokenVersion1] token minted by
// this connector for exactly app, dst, and peer.
func (c *connector) verifyToken(token []byte, app string, dst netip.Addr, peer key.NodePublic) bool {
	if len(token) != 1+tokenMACLen || token[0] != tokenVersion1 {
		return false
	}
	if len(app) > math.MaxUint16 {
		return false
	}

	c.mu.Lock()
	secret := c.tokenSecret
	c.mu.Unlock()

	return hmac.Equal(token[1:], tokenMAC(secret, app, dst, peer))
}

// tokenMAC returns the truncated HMAC-SHA-256 that authenticates a token's
// inputs,
//
// The token is version(1) | mac(16), where mac is
//
//	HMAC-SHA-256(tokenSecret, version | uint16(len(app)) | app | dst | peer)
//
// truncated to [tokenMACLen] bytes. dst is canonicalized to its 16-byte form so
// that the IPv4 and IPv4-in-IPv6 representations of the same address produce the
// same token. app is length-prefixed because it is the only variable-width
// input, which keeps the concatenation unambiguous. An app name longer than the
// uint16 length prefix can hold is rejected rather than minted, since a
// truncated prefix would reintroduce that ambiguity.
func tokenMAC(secret [tokenSecretLen]byte, app string, dst netip.Addr, peer key.NodePublic) []byte {
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte{tokenVersion1})
	var appLen [2]byte
	binary.BigEndian.PutUint16(appLen[:], uint16(len(app)))
	mac.Write(appLen[:])
	mac.Write([]byte(app))
	dstCanon := dst.Unmap().As16()
	mac.Write(dstCanon[:])
	peerRaw := peer.Raw32()
	mac.Write(peerRaw[:])
	return mac.Sum(nil)[:tokenMACLen]
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import "crypto/rand"

// tokenSecretLen is the length in bytes of the connector's token secret. It is
// the recommended key size for HMAC-SHA-256, which is used to mint and verify
// destination IP tokens.
const tokenSecretLen = 32

// newTokenSecret returns a fresh random token secret.
func newTokenSecret() [tokenSecretLen]byte {
	var secret [tokenSecretLen]byte
	rand.Read(secret[:])
	return secret
}

// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package noise

// Note that these types are deliberately separate from the types/key
// package. That package defines generic curve25519 keys, without
// consideration for how those keys are used. We don't want to
// encourage mixing machine keys, node keys, and whatever else we
// might use curve25519 for.
//
// Furthermore, the implementation in types/key does some work that is
// unnecessary for machine keys, and results in a harder to follow
// implementation. In particular, machine keys do not need to be
// clamped per the curve25519 spec because they're only used with the
// X25519 operation, and the X25519 operation defines its own clamping
// and sanity checking logic. Thus, these keys must be used only with
// this Noise protocol implementation, and the easiest way to ensure
// that is a different type.

// PrivateKey is a Tailscale machine private key.
type PrivateKey [32]byte

// PublicKey is a Tailscale machine public key.
type PublicKey [32]byte

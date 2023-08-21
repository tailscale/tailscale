// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build js || wasm
// +build js wasm

package magicsock

// isBadEndpointErr checks if err is one which is known to report that an
// endpoint can no longer be sent to. It is not exhaustive, but covers known
// cases.
func isBadEndpointErr(err error) bool {
	return false
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios

package ipnlocal

func (b *LocalBackend) ShouldRunRelayServer() bool {
	return false
}

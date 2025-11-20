// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

// ProfileAccess is a bitmask representing the requested, required, or granted
// access rights to an [ipn.LoginProfile].
//
// It is not to be written to disk or transmitted over the network in its integer form,
// but rather serialized to a string or other format if ever needed.
type ProfileAccess uint

// Define access rights that might be granted or denied on a per-profile basis.
const (
	// Disconnect is required to disconnect (or switch from) a Tailscale profile.
	Disconnect = ProfileAccess(1 << iota)
)

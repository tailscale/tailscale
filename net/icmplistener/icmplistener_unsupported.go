// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !(linux || darwin)

package icmplistener

import "net"

// ListenConfig on this platform is simply a wrapper around net.ListenConfig.
type ListenConfig struct {
	net.ListenConfig
}

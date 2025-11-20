// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netlogfunc defines types for network logging.
package netlogfunc

import (
	"net/netip"

	"tailscale.com/types/ipproto"
)

// ConnectionCounter is a function for counting packets and bytes
// for a particular connection.
type ConnectionCounter func(proto ipproto.Proto, src, dst netip.AddrPort, packets, bytes int, recv bool)

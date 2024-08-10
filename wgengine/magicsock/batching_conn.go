// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"tailscale.com/types/nettype"
)

var (
	// This acts as a compile-time check for our usage of ipv6.Message in
	// batchingConn for both IPv6 and IPv4 operations.
	_ ipv6.Message = ipv4.Message{}
)

// batchingConn is a nettype.PacketConn that provides batched i/o.
type batchingConn interface {
	nettype.PacketConn
	ReadBatch(msgs []ipv6.Message, flags int) (n int, err error)
	WriteBatchTo(buffs [][]byte, addr netip.AddrPort) error
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package batching implements a socket optimized for increased throughput.
package batching

import (
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"tailscale.com/envknob"
	"tailscale.com/net/packet"
	"tailscale.com/types/nettype"
)

// BatchSizeFromEnv returns ideal, unless the TS_DEBUG_WG_BATCH_SIZE
// environment variable is set to a positive integer, in which case it returns
// that value clamped to [1, ideal].
//
// Batch size determines how much packet memory wireguard-go pins per reader
// goroutine (batch size × 64 KiB message buffers per reader, ~32 MiB total at
// the Linux default of 128), so memory-budget tests set the env var to 1 to
// approximate the configuration used on memory-constrained (mobile)
// platforms, where batch size is always 1.
func BatchSizeFromEnv(ideal int) int {
	if v, ok := envknob.LookupInt("TS_DEBUG_WG_BATCH_SIZE"); ok && v > 0 {
		return min(v, ideal)
	}
	return ideal
}

var (
	// This acts as a compile-time check for our usage of ipv6.Message in
	// [Conn] for both IPv6 and IPv4 operations.
	_ ipv6.Message = ipv4.Message{}
)

// Conn is a [nettype.PacketConn] that provides batched i/o using
// platform-specific optimizations, e.g. {recv,send}mmsg & UDP GSO/GRO.
//
// Conn does not support single packet reads (see ReadFromUDPAddrPort docs). It
// is the caller's responsibility to use the appropriate read API where a
// [nettype.PacketConn] has been upgraded to support batched i/o.
//
// Conn originated from (and is still used by) magicsock where its API was
// strongly influenced by [wireguard-go/conn.Bind] constraints, namely
// wireguard-go's ownership of packet memory.
type Conn interface {
	nettype.PacketConn
	// ReadFromUDPAddrPort always returns an error, as UDP GRO is incompatible
	// with single packet reads. A single datagram may be multiple, coalesced
	// datagrams, and this API lacks the ability to pass that context.
	//
	// TODO: consider detaching Conn from [nettype.PacketConn]
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	// ReadBatch reads messages from [Conn] into msgs. It returns the number of
	// messages the caller should evaluate for nonzero len, as a zero len
	// message may fall on either side of a nonzero.
	//
	// Each [ipv6.Message.OOB] must be sized to at least MinControlMessageSize().
	ReadBatch(msgs []ipv6.Message, flags int) (n int, err error)
	// WriteBatchTo writes buffs to addr.
	//
	// If geneve.VNI.IsSet(), then geneve is encoded into the space preceding
	// offset, and offset must equal [packet.GeneveFixedHeaderLength]. If
	// !geneve.VNI.IsSet() then the space preceding offset is ignored.
	//
	// len(buffs) must be <= batchSize supplied in TryUpgradeToConn().
	//
	// WriteBatchTo may return a [neterror.ErrUDPGSODisabled] error if UDP GSO
	// was disabled as a result of a send error.
	WriteBatchTo(buffs [][]byte, addr netip.AddrPort, geneve packet.GeneveHeader, offset int) error
}

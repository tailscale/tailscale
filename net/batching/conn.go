// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package batching implements a socket optimized for increased throughput.
package batching

import (
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"tailscale.com/net/packet"
	"tailscale.com/types/nettype"
)

var (
	// This acts as a compile-time check for our usage of ipv6.Message in
	// [Conn] for both IPv6 and IPv4 operations.
	_ ipv6.Message = ipv4.Message{}
)

// ReceivedPacket describes a packet read by [Conn.ReadBatch].
type ReceivedPacket struct {
	// Offset is the starting byte offset into the slab supplied to [Conn.ReadBatch].
	Offset int
	// Size is the size of the packet.
	Size int
	// Source is the source address that sent the packet.
	Source netip.AddrPort
}

const (
	// ReadSlabMultiple is the minimum slab length accepted by [Conn.ReadBatch],
	// and is the suggested multiple when passing a larger value.
	ReadSlabMultiple = 1<<16 - 1
	// MinimumReadBatchSize is the minimum number of packets descriptors accepted
	// by [Conn.ReadBatch].
	MinimumReadBatchSize = udpGROCountMax
	// MaximumWriteBatchSize is the maximum number of buffs accepted by
	// [Conn.WriteBatchTo].
	MaximumWriteBatchSize = 128
	// udpGROCountMax is the maximum number of datagrams the kernel will coalesce
	// together to present in a single recvmmsg() slot.
	udpGROCountMax = 64
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
	// ReadBatch reads datagrams from [Conn] into slab, and describes them in
	// packets. It returns the number of populated packet descriptors. A single
	// GRO-coalesced datagram may produce multiple descriptors.
	//
	// packets must have a length >= [MinimumReadBatchSize]. slab must have a
	// length >= [ReadSlabMultiple]. ReadBatch reads only as many datagrams as
	// both arguments can accommodate.
	ReadBatch(slab []byte, packets []ReceivedPacket) (n int, err error)
	// WriteBatchTo writes buffs to addr.
	//
	// If geneve.VNI.IsSet(), then geneve is encoded into the space preceding
	// offset, and offset must equal [packet.GeneveFixedHeaderLength]. If
	// !geneve.VNI.IsSet() then the space preceding offset is ignored.
	//
	// len(buffs) must be <= [MaximumWriteBatchSize].
	//
	// WriteBatchTo may return a [neterror.ErrUDPGSODisabled] error if UDP GSO
	// was disabled as a result of a send error.
	WriteBatchTo(buffs [][]byte, addr netip.AddrPort, geneve packet.GeneveHeader, offset int) error
}

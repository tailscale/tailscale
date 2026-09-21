// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package pktinfo lets a UDP server learn the local address each datagram
// was sent to and reply from that same address.
//
// A server on a wildcard socket otherwise replies from whatever source
// address the kernel picks by routing to the client. On a multi-homed host
// that is the default route's address, not necessarily the one the request
// arrived on, which breaks clients and middleboxes (conntrack, policy
// routing) that expect the reply to come from the address they sent to.
//
// The functions operate on raw socket control message bytes, as used by
// [net.UDPConn.ReadMsgUDPAddrPort], [net.UDPConn.WriteMsgUDPAddrPort], and
// the OOB fields of golang.org/x/net/ipv4 and ipv6 batch messages.
//
// It is only implemented on Linux. Elsewhere, [Enable] returns
// [errors.ErrUnsupported].
package pktinfo

import (
	"net"
	"net/netip"
)

// Enable asks the kernel to include, in the control messages of each
// datagram received on pc, the local address the datagram was sent to.
// See [Dst]. A wildcard "udp" socket is dual-stack and receives IPv4
// datagrams too; both families are handled.
func Enable(pc *net.UDPConn) error {
	return enable(pc)
}

// Dst returns the local destination address recorded in the control
// messages oob of a received datagram, or the zero [netip.Addr] if there
// is none. IPv4 addresses received on a dual-stack socket are returned
// unmapped.
func Dst(oob []byte) netip.Addr {
	return dst(oob)
}

// AppendSrc appends to b the control message that makes a datagram sent
// with it be sent from the local address src. It returns b unchanged if
// src isn't a usable source address (invalid, unspecified, or multicast).
//
// Only the source address is pinned. The interface index is left zero so
// that routing (including policy routing) still decides the egress
// interface.
func AppendSrc(b []byte, src netip.Addr) []byte {
	if !src.IsValid() || src.IsUnspecified() || src.IsMulticast() {
		return b
	}
	return appendSrc(b, src)
}

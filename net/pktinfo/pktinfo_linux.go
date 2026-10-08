// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package pktinfo

import (
	"encoding/binary"
	"math/bits"
	"net"
	"net/netip"
	"slices"

	"golang.org/x/sys/unix"
)

// cmsgLenSize is the size of struct cmsghdr's cmsg_len field, a size_t,
// which is the word size on every Linux ABI Go supports.
const cmsgLenSize = bits.UintSize / 8

// appendSrc assumes cmsg_len is followed by exactly the two int32 fields
// cmsg_level and cmsg_type. Fail to compile otherwise.
var _ [0]struct{} = [unix.SizeofCmsghdr - cmsgLenSize - 8]struct{}{}

func enable(pc *net.UDPConn) error {
	// A wildcard "udp" socket is AF_INET6 (dual-stack) and its
	// LocalAddr is "[::]"; a "udp4" or IPv4-bound socket is AF_INET.
	v6 := true
	if la, ok := pc.LocalAddr().(*net.UDPAddr); ok && la.IP.To4() != nil {
		v6 = false
	}
	rc, err := pc.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	err = rc.Control(func(fd uintptr) {
		if v6 {
			sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
			if sockErr != nil {
				return
			}
		}
		// On a dual-stack socket, IPV6_RECVPKTINFO alone reports
		// IPv4 datagrams' header destination as a v4-mapped address,
		// which for a broadcast datagram is the broadcast address:
		// useless as a reply source. IP_PKTINFO applies to the IPv4
		// datagrams on the same socket and carries ipi_spec_dst, the
		// unicast address the kernel considers ours for replying.
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
	})
	if err != nil {
		return err
	}
	return sockErr
}

func dst(oob []byte) netip.Addr {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}
	}
	var v6 netip.Addr
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_PKTINFO:
			// struct in_pktinfo is ipi_ifindex, ipi_spec_dst, ipi_addr.
			// This is the preferred answer; see enable.
			if len(m.Data) >= unix.SizeofInet4Pktinfo {
				return netip.AddrFrom4([4]byte(m.Data[4:8]))
			}
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_PKTINFO:
			// struct in6_pktinfo is ipi6_addr followed by ipi6_ifindex.
			if len(m.Data) >= unix.SizeofInet6Pktinfo {
				v6 = netip.AddrFrom16([16]byte(m.Data[:16])).Unmap()
			}
		}
	}
	return v6
}

// appendSrc builds the control message by hand rather than with
// golang.org/x/net/ipv6, whose ControlMessage silently drops a v4-mapped
// Src, or with [unix.PktInfo4] and [unix.PktInfo6], which allocate per call.
//
// The cmsg level follows the address family of src, not the socket's.
// Linux accepts an IP_PKTINFO cmsg on a dual-stack AF_INET6 socket when
// the destination is IPv4, since such sends go through the IPv4 path.
func appendSrc(b []byte, src netip.Addr) []byte {
	var level, typ, dataLen int
	if src.Is4() {
		level, typ, dataLen = unix.SOL_IP, unix.IP_PKTINFO, unix.SizeofInet4Pktinfo
	} else {
		level, typ, dataLen = unix.SOL_IPV6, unix.IPV6_PKTINFO, unix.SizeofInet6Pktinfo
	}
	start := len(b)
	b = slices.Grow(b, unix.CmsgSpace(dataLen))[:start+unix.CmsgSpace(dataLen)]
	clear(b[start:])

	hdr := b[start:]
	switch cmsgLenSize {
	case 8:
		binary.NativeEndian.PutUint64(hdr, uint64(unix.CmsgLen(dataLen)))
	case 4:
		binary.NativeEndian.PutUint32(hdr, uint32(unix.CmsgLen(dataLen)))
	}
	binary.NativeEndian.PutUint32(hdr[cmsgLenSize:], uint32(level))
	binary.NativeEndian.PutUint32(hdr[cmsgLenSize+4:], uint32(typ))

	data := hdr[unix.CmsgLen(0):]
	if src.Is4() {
		// struct in_pktinfo is ipi_ifindex, ipi_spec_dst, ipi_addr.
		a := src.As4()
		copy(data[4:], a[:])
	} else {
		// struct in6_pktinfo is ipi6_addr followed by ipi6_ifindex.
		a := src.As16()
		copy(data, a[:])
	}
	return b
}

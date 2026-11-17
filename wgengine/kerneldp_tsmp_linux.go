// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_tswg

package wgengine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"golang.org/x/sys/unix"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/types/ipproto"
)

// This file has the kernel data plane's IP-level plumbing between the
// kernel's tswg device and tstun: packets that tailscaled itself sends to
// peers (TSMP pings, pongs and disco key advertisements, ICMP echo
// replies, netstack) and the TSMP packets that peers send to it.
//
// With wireguard-go, all of those pass through the tstun.Wrapper between
// the TUN device and wireguard-go. In kernel mode, packets don't pass
// through tailscaled, so:
//
//   - tstun's injected outbound packets go to sendIPPacket (via
//     tstun.Wrapper.SetOutboundInjectHook), which writes them, IP header
//     and all, to a raw IP socket bound to the tswg device, so the kernel
//     routes them into the device, which encrypts them to the peer;
//   - TSMP packets (IP protocol 99) that arrive on the tswg device are
//     read from raw sockets for that protocol, bound to the device, and
//     fed to tstun as if they came from wireguard-go, which handles them
//     as usual (answering pings, delivering pongs, learning disco keys).
//     With such a raw socket open, the kernel doesn't send ICMP protocol
//     unreachable errors for TSMP.

// ipSockets are the kernel data plane's raw IP sockets.
type ipSockets struct {
	send4, send6 int      // raw IPPROTO_RAW sockets, header included; or -1
	recv4, recv6 *os.File // raw IPPROTO_TSMP sockets; or nil
}

// rawSocket returns a raw IP socket for family and proto, bound to the
// network device ifname.
func rawSocket(family, proto int, ifname string) (int, error) {
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return -1, err
	}
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifname); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// openIPSockets opens the raw sockets on k's device. The IPv6 sockets are
// optional, since IPv6 might be disabled.
func (k *kernelDataplane) openIPSockets() (*ipSockets, error) {
	s := &ipSockets{send4: -1, send6: -1}
	var err error
	if s.send4, err = rawSocket(unix.AF_INET, unix.IPPROTO_RAW, k.ifname); err != nil {
		return nil, fmt.Errorf("raw IPv4 send socket: %w", err)
	}
	fd, err := rawSocket(unix.AF_INET, int(ipproto.TSMP), k.ifname)
	if err != nil {
		s.close()
		return nil, fmt.Errorf("raw IPv4 TSMP socket: %w", err)
	}
	s.recv4, err = pollableFile(fd, "tswg-tsmp4")
	if err != nil {
		s.close()
		return nil, err
	}

	if fd, err := rawSocket(unix.AF_INET6, unix.IPPROTO_RAW, k.ifname); err == nil {
		s.send6 = fd
	} else {
		k.logf("no raw IPv6 send socket: %v", err)
	}
	if fd, err := rawSocket(unix.AF_INET6, int(ipproto.TSMP), k.ifname); err == nil {
		// IPv6 raw sockets don't return the IP header, so ask for the
		// destination address and hop limit to rebuild it.
		err := errors.Join(
			unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1),
			unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, 1))
		if err == nil {
			s.recv6, err = pollableFile(fd, "tswg-tsmp6")
		} else {
			unix.Close(fd)
		}
		if err != nil {
			k.logf("no raw IPv6 TSMP socket: %v", err)
		}
	} else {
		k.logf("no raw IPv6 TSMP socket: %v", err)
	}
	return s, nil
}

// pollableFile wraps fd in an *os.File that uses the Go netpoller, so that
// reads block in the poller (and closing the file unblocks them).
func pollableFile(fd int, name string) (*os.File, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func (s *ipSockets) close() {
	for _, fd := range []int{s.send4, s.send6} {
		if fd >= 0 {
			unix.Close(fd)
		}
	}
	for _, f := range []*os.File{s.recv4, s.recv6} {
		if f != nil {
			f.Close()
		}
	}
}

// sendIPPacket is the tstun outbound inject hook: it sends pkt, a complete
// IPv4 or IPv6 packet that tailscaled generated for a peer, into the
// kernel's tswg device.
func (k *kernelDataplane) sendIPPacket(pkt []byte) {
	var p packet.Parsed
	p.Decode(pkt)
	dst := p.Dst.Addr()
	var err error
	switch {
	case p.IPVersion == 4 && k.ipSocks.send4 >= 0:
		err = unix.Sendto(k.ipSocks.send4, pkt, 0, &unix.SockaddrInet4{Addr: dst.As4()})
	case p.IPVersion == 6 && k.ipSocks.send6 >= 0:
		err = unix.Sendto(k.ipSocks.send6, pkt, 0, &unix.SockaddrInet6{Addr: dst.As16()})
	default:
		err = fmt.Errorf("can't send IPv%d packet", p.IPVersion)
	}
	if err != nil {
		k.logf("sending %d-byte %v packet to %v: %v", len(pkt), p.IPProto, dst, err)
	}
}

// readTSMP4 reads the TSMP packets that arrive on the device over IPv4 and
// passes them to tstun. IPv4 raw sockets return the whole IP packet.
func (k *kernelDataplane) readTSMP4(tun *tstun.Wrapper) {
	buf := make([]byte, tstun.WritePacketStartOffset+tstun.MaxPacketSize)
	for {
		n, err := k.ipSocks.recv4.Read(buf[tstun.WritePacketStartOffset:])
		if err != nil {
			if k.ctx.Err() == nil {
				k.logf("reading IPv4 TSMP: %v", err)
			}
			return
		}
		k.deliverTSMP(tun, buf[:tstun.WritePacketStartOffset+n])
	}
}

// readTSMP6 is like readTSMP4 for IPv6, whose raw sockets return only the
// payload, so it rebuilds the IPv6 header from the source address and the
// destination address and hop limit control messages.
func (k *kernelDataplane) readTSMP6(tun *tstun.Wrapper) {
	const hdrLen = 40
	buf := make([]byte, tstun.WritePacketStartOffset+hdrLen+tstun.MaxPacketSize)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo)+unix.CmsgSpace(4))
	rc, err := k.ipSocks.recv6.SyscallConn()
	if err != nil {
		k.logf("reading IPv6 TSMP: %v", err)
		return
	}
	payload := buf[tstun.WritePacketStartOffset+hdrLen:]
	for {
		var n, oobn int
		var from unix.Sockaddr
		var rerr error
		err := rc.Read(func(fd uintptr) bool {
			n, oobn, _, from, rerr = unix.Recvmsg(int(fd), payload, oob, 0)
			return rerr != unix.EAGAIN
		})
		if err == nil {
			err = rerr
		}
		if err != nil {
			if k.ctx.Err() == nil {
				k.logf("reading IPv6 TSMP: %v", err)
			}
			return
		}
		src, ok := from.(*unix.SockaddrInet6)
		if !ok {
			continue
		}
		dst, hopLimit, ok := parseIPv6RecvCmsgs(oob[:oobn])
		if !ok {
			continue
		}
		h := buf[tstun.WritePacketStartOffset:][:hdrLen]
		clear(h)
		h[0] = 6 << 4
		binary.BigEndian.PutUint16(h[4:6], uint16(n))
		h[6] = byte(ipproto.TSMP)
		h[7] = hopLimit
		copy(h[8:24], src.Addr[:])
		dst16 := dst.As16()
		copy(h[24:40], dst16[:])
		k.deliverTSMP(tun, buf[:tstun.WritePacketStartOffset+hdrLen+n])
	}
}

// parseIPv6RecvCmsgs returns the destination address (IPV6_PKTINFO) and hop
// limit (IPV6_HOPLIMIT) from an IPv6 raw socket's control messages.
func parseIPv6RecvCmsgs(oob []byte) (dst netip.Addr, hopLimit uint8, ok bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	hopLimit = 64
	for _, m := range msgs {
		if m.Header.Level != unix.IPPROTO_IPV6 {
			continue
		}
		switch m.Header.Type {
		case unix.IPV6_PKTINFO:
			if len(m.Data) >= unix.SizeofInet6Pktinfo {
				// struct in6_pktinfo { in6_addr addr; int ifindex; }
				dst = netip.AddrFrom16([16]byte(m.Data[:16]))
				ok = true
			}
		case unix.IPV6_HOPLIMIT:
			if len(m.Data) >= 4 {
				hopLimit = uint8(binary.NativeEndian.Uint32(m.Data))
			}
		}
	}
	return dst, hopLimit, ok
}

// deliverTSMP passes buf, a TSMP packet from a peer starting at offset
// tstun.WritePacketStartOffset, to tstun, as wireguard-go would.
func (k *kernelDataplane) deliverTSMP(tun *tstun.Wrapper, buf []byte) {
	if _, err := tun.Write([][]byte{buf}, tstun.WritePacketStartOffset); err != nil {
		k.logf("delivering TSMP packet: %v", err)
	}
}

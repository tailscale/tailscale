// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"tailscale.com/disco"
	"tailscale.com/envknob"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/util/clientmetric"
)

const (
	udpHeaderSize          = 8
	ipv6HeaderSize         = 40
	ipv6FragmentHeaderSize = 8
)

// Debug tweakables
var (
	// Enable/disable using AF_PACKET sockets
	debugDisableAF_PACKET = envknob.Bool("TS_DEBUG_DISABLE_AF_PACKET")
)

// Convert our disco magic number into a uint32 and uint16 to test
// against. We panic on an incorrect length here rather than try to be
// generic with our BPF instructions below.
//
// Note that BPF uses network byte order (big-endian) when loading data
// from a packet, so that is what we use to generate our magic numbers.
var magic1, magic2 = (func() (uint32, uint16) {
	if len(disco.Magic) != 6 {
		panic("expected disco.Magic to be of length 6")
	}
	r1 := binary.BigEndian.Uint32([]byte(disco.Magic[0:4]))
	r2 := binary.BigEndian.Uint16([]byte(disco.Magic[4:6]))
	return r1, r2
})()

// These are our BPF filters that we use for testing packets.
var (
	magicsockFilterV4 = []bpf.Instruction{
		// Protocol is guaranteed to be UDP because we told
		// net.ListenPacket we wanted a UDP tap.

		// Disco packets are so small they should never get
		// fragmented, and we don't want to handle reassembly.
		bpf.LoadAbsolute{Off: 6, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x2000, SkipTrue: 7, SkipFalse: 0},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6, SkipFalse: 0},

		// Load IP header length into X register.
		bpf.LoadMemShift{Off: 0},

		// Get the first 4 bytes of the UDP packet, compare with our magic number
		bpf.LoadIndirect{Off: udpHeaderSize, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: magic1, SkipTrue: 0, SkipFalse: 3},

		// Compare the next 2 bytes
		bpf.LoadIndirect{Off: udpHeaderSize + 4, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(magic2), SkipTrue: 0, SkipFalse: 1},

		// Accept the whole packet
		bpf.RetConstant{Val: 0xFFFFFFFF},

		// Skip the packet
		bpf.RetConstant{Val: 0x0},
	}

	// IPv6 is more complicated to filter, since we can have 0-to-N
	// extension headers following the IPv6 header. Since BPF can't
	// loop, we can't really parse these in a general way; instead, we
	// simply handle the case where we have no extension headers; any
	// packets with headers will be skipped. IPv6 extension headers
	// are sufficiently uncommon that we're willing to accept false
	// negatives here.
	//
	// The "proper" way to handle this would be to do minimal parsing in
	// BPF and more in-depth parsing of all IPv6 packets in userspace, but
	// on systems with a high volume of UDP that would be unacceptably slow
	// and thus we'd rather be conservative here and possibly not receive
	// disco packets rather than slow down the system.
	magicsockFilterV6 = []bpf.Instruction{
		// Transport protocol is guaranteed to be UDP by
		// net.ListenPacket, but we still have to check the "Next
		// Header" field to eliminate packets that have IPv6 extension
		// headers. Extension headers are very uncommon on real
		// networks, so we don't try to handle them.
		bpf.LoadAbsolute{Off: 6, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(ipproto.UDP), SkipTrue: 0, SkipFalse: 5},

		// If we get here, we have a UDP packet; compare with our magic
		// number. Start by loading and comparing the first 4 bytes of
		// the UDP packet.
		bpf.LoadAbsolute{Off: ipv6HeaderSize + udpHeaderSize, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: magic1, SkipTrue: 0, SkipFalse: 3},

		// Compare the next 2 bytes
		bpf.LoadIndirect{Off: ipv6HeaderSize + udpHeaderSize + 4, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(magic2), SkipTrue: 0, SkipFalse: 1},

		// Accept the whole packet
		bpf.RetConstant{Val: 0xFFFFFFFF},

		// Skip the packet
		bpf.RetConstant{Val: 0x0},
	}
)

// listenRawDisco starts listening for disco packets on the given
// address family, which must be "ip4" or "ip6", using a raw socket
// and BPF filter.
// https://github.com/tailscale/tailscale/issues/3824
func (c *Conn) listenRawDisco(family string) (io.Closer, error) {
	if debugDisableAF_PACKET {
		return nil, errors.New("raw disco listening disabled by debug flag")
	}

	var (
		network string
		addr    string
		prog    []bpf.Instruction
	)
	switch family {
	case "ip4":
		network = "ip4:17"
		addr = "0.0.0.0"
		prog = magicsockFilterV4
	case "ip6":
		network = "ip6:17"
		addr = "::"
		prog = magicsockFilterV6
	default:
		return nil, fmt.Errorf("unsupported address family %q", family)
	}

	asm, err := bpf.Assemble(prog)
	if err != nil {
		return nil, fmt.Errorf("assembling filter: %w", err)
	}

	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, fmt.Errorf("creating packet conn: %w", err)
	}

	if err := setBPF(pc, asm); err != nil {
		pc.Close()
		return nil, fmt.Errorf("installing BPF filter: %w", err)
	}

	go c.receiveDisco(pc)
	return pc, nil
}

func (c *Conn) receiveDisco(pc net.PacketConn) {
	var buf [1500]byte
	for {
		n, src, err := pc.ReadFrom(buf[:])
		if err == net.ErrClosed {
			return
		} else if err != nil {
			c.logf("disco raw reader failed: %v", err)
			return
		}
		if n < udpHeaderSize {
			// Too small to be a valid UDP datagram, drop.
			continue
		}
		srcIP, ok := netip.AddrFromSlice(src.(*net.IPAddr).IP)
		if !ok {
			c.logf("[unexpected] PacketConn.ReadFrom returned not-an-IP %v in from", src)
			continue
		}
		srcPort := binary.BigEndian.Uint16(buf[:2])

		var metricOK, metricInvalid *clientmetric.Metric
		if srcIP.Is4() {
			metricOK = metricRecvDiscoPacketIPv4
			metricInvalid = metricRecvDiscoPacketInvalidIPv4
		} else {
			metricOK = metricRecvDiscoPacketIPv6
			metricInvalid = metricRecvDiscoPacketInvalidIPv6
		}

		if c.handleDiscoMessage(buf[udpHeaderSize:n], netip.AddrPortFrom(srcIP, srcPort), key.NodePublic{}) {
			metricOK.Add(1)
		} else {
			metricInvalid.Add(1)
		}
	}
}

// setBPF installs filter as the BPF filter on conn.
// Ideally we would just use SetBPF as implemented in x/net/ipv4,
// but x/net/ipv6 doesn't implement it. And once you've written
// this code once, it turns out to be address family agnostic, so
// we might as well use it on both and get to use a net.PacketConn
// directly for both families instead of being stuck with
// different types.
func setBPF(conn net.PacketConn, filter []bpf.RawInstruction) error {
	sc, err := conn.(*net.IPConn).SyscallConn()
	if err != nil {
		return err
	}
	prog := &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0])),
	}
	var setErr error
	err = sc.Control(func(fd uintptr) {
		setErr = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog)
	})
	if err != nil {
		return err
	}
	if setErr != nil {
		return err
	}
	return nil
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_listenrawdisco

package magicsock

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/mdlayher/socket"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/cpu"
	"golang.org/x/sys/unix"
	"tailscale.com/disco"
	"tailscale.com/envknob"
	"tailscale.com/net/netns"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	udpHeaderSize = 8

	// discoMinHeaderSize is the minimum size of the disco header in bytes.
	discoMinHeaderSize = len(disco.Magic) + 32 /* key length */ + disco.NonceLen
)

var (
	// Opt-in for using raw sockets to receive disco traffic; added for
	// #13140 and replaces the older "TS_DEBUG_DISABLE_RAW_DISCO".
	envknobEnableRawDisco = envknob.RegisterBool("TS_ENABLE_RAW_DISCO")
)

// debugRawDiscoReads enables logging of raw disco reads.
var debugRawDiscoReads = envknob.RegisterBool("TS_DEBUG_RAW_DISCO")

// These are our BPF filters that we use for testing packets.
var (
	magicsockFilterV4 = []bpf.Instruction{
		// For raw sockets (with ETH_P_IP set), the BPF program
		// receives the entire IPv4 packet, but not the Ethernet
		// header.

		// Double-check that this is a UDP packet; we shouldn't be
		// seeing anything else given how we create our AF_PACKET
		// socket, but an extra check here is cheap, and matches the
		// check that we do in the IPv6 path.
		bpf.LoadAbsolute{Off: 9, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(ipproto.UDP), SkipTrue: 1, SkipFalse: 0},
		bpf.RetConstant{Val: 0x0},

		// Disco packets are so small they should never get
		// fragmented, and we don't want to handle reassembly.
		bpf.LoadAbsolute{Off: 6, Size: 2},
		// More Fragments bit set means this is part of a fragmented packet.
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x2000, SkipTrue: 8, SkipFalse: 0},
		// Non-zero fragment offset with MF=0 means this is the last
		// fragment of packet.
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 7, SkipFalse: 0},

		// Load IP header length into X register.
		bpf.LoadMemShift{Off: 0},

		// Verify that we have a packet that's big enough to (possibly)
		// contain a disco packet.
		//
		// The length of an IPv4 disco packet is composed of:
		// - 8 bytes for the UDP header
		// - N bytes for the disco packet header
		//
		// bpf will implicitly return 0 ("skip") if attempting an
		// out-of-bounds load, so we can check the length of the packet
		// loading a byte from that offset here. We subtract 1 byte
		// from the offset to ensure that we accept a packet that's
		// exactly the minimum size.
		//
		// We use LoadIndirect; since we loaded the start of the packet's
		// payload into the X register, above, we don't need to add
		// ipv4.HeaderLen to the offset (and this properly handles IPv4
		// extensions).
		bpf.LoadIndirect{Off: uint32(udpHeaderSize + discoMinHeaderSize - 1), Size: 1},

		// Get the first 4 bytes of the UDP packet, compare with our magic number
		bpf.LoadIndirect{Off: udpHeaderSize, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: discoMagic1, SkipTrue: 0, SkipFalse: 3},

		// Compare the next 2 bytes
		bpf.LoadIndirect{Off: udpHeaderSize + 4, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(discoMagic2), SkipTrue: 0, SkipFalse: 1},

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
		// Do a bounds check to ensure we have enough space for a disco
		// packet; see the comment in the IPv4 BPF program for more
		// details.
		bpf.LoadAbsolute{Off: uint32(ipv6.HeaderLen + udpHeaderSize + discoMinHeaderSize - 1), Size: 1},

		// Verify that the 'next header' value of the IPv6 packet is
		// UDP, which is what we're expecting; if it's anything else
		// (including extension headers), we skip the packet.
		bpf.LoadAbsolute{Off: 6, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(ipproto.UDP), SkipTrue: 0, SkipFalse: 5},

		// Compare with our magic number. Start by loading and
		// comparing the first 4 bytes of the UDP payload.
		bpf.LoadAbsolute{Off: ipv6.HeaderLen + udpHeaderSize, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: discoMagic1, SkipTrue: 0, SkipFalse: 3},

		// Compare the next 2 bytes
		bpf.LoadAbsolute{Off: ipv6.HeaderLen + udpHeaderSize + 4, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: discoMagic2, SkipTrue: 0, SkipFalse: 1},

		// Accept the whole packet
		bpf.RetConstant{Val: 0xFFFFFFFF},

		// Skip the packet
		bpf.RetConstant{Val: 0x0},
	}

	testDiscoPacket = []byte{
		// Disco magic
		0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac,
		// Sender key
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		// Nonce
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	}
)

// listenRawDisco starts listening for disco packets on the given
// address family, which must be "ip4" or "ip6", using a raw socket
// and BPF filter.
// https://github.com/tailscale/tailscale/issues/3824
func (c *Conn) listenRawDisco(family string) (io.Closer, error) {
	if !envknobEnableRawDisco() {
		// Return an 'errors.ErrUnsupported' to prevent the callee from
		// logging; when we switch this to an opt-out (vs. an opt-in),
		// drop the ErrUnsupported so that the callee logs that it was
		// disabled.
		return nil, fmt.Errorf("raw disco not enabled: %w", errors.ErrUnsupported)
	}

	// https://github.com/tailscale/tailscale/issues/5607
	if !netns.UseSocketMark() {
		return nil, errors.New("raw disco listening disabled, SO_MARK unavailable")
	}

	var (
		udpnet   string
		addr     string
		proto    int
		testAddr netip.AddrPort
		prog     []bpf.Instruction
	)
	switch family {
	case "ip4":
		udpnet = "udp4"
		addr = "0.0.0.0"
		proto = ethernetProtoIPv4()
		testAddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1)
		prog = magicsockFilterV4
	case "ip6":
		udpnet = "udp6"
		addr = "::"
		proto = ethernetProtoIPv6()
		testAddr = netip.AddrPortFrom(netip.IPv6Loopback(), 1)
		prog = magicsockFilterV6
	default:
		return nil, fmt.Errorf("unsupported address family %q", family)
	}

	asm, err := bpf.Assemble(prog)
	if err != nil {
		return nil, fmt.Errorf("assembling filter: %w", err)
	}

	sock, err := socket.Socket(
		unix.AF_PACKET,
		unix.SOCK_DGRAM,
		proto,
		"afpacket",
		nil, // no config
	)
	if err != nil {
		return nil, fmt.Errorf("creating AF_PACKET socket: %w", err)
	}

	if err := sock.SetBPF(asm); err != nil {
		sock.Close()
		return nil, fmt.Errorf("installing BPF filter: %w", err)
	}

	// If all the above succeeds, we should be ready to receive. Just
	// out of paranoia, check that we do receive a well-formed disco
	// packet.
	tc, err := net.ListenPacket(udpnet, net.JoinHostPort(addr, "0"))
	if err != nil {
		sock.Close()
		return nil, fmt.Errorf("creating disco test socket: %w", err)
	}
	defer tc.Close()
	if _, err := tc.(*net.UDPConn).WriteToUDPAddrPort(testDiscoPacket, testAddr); err != nil {
		sock.Close()
		return nil, fmt.Errorf("writing disco test packet: %w", err)
	}

	const selfTestTimeout = 100 * time.Millisecond
	if err := sock.SetReadDeadline(time.Now().Add(selfTestTimeout)); err != nil {
		sock.Close()
		return nil, fmt.Errorf("setting socket timeout: %w", err)
	}

	var (
		ctx = context.Background()
		buf [1500]byte
	)
	for {
		n, _, err := sock.Recvfrom(ctx, buf[:], 0)
		if err != nil {
			sock.Close()
			return nil, fmt.Errorf("reading during raw disco self-test: %w", err)
		}

		_ /* src */, _ /* dst */, payload := parseUDPPacket(buf[:n], family == "ip6")
		if payload == nil {
			continue
		}
		if !bytes.Equal(payload, testDiscoPacket) {
			c.discoLogf("listenRawDisco: self-test: received mismatched UDP packet of %d bytes", len(payload))
			continue
		}
		c.logf("[v1] listenRawDisco: self-test passed for %s", family)
		break
	}
	sock.SetReadDeadline(time.Time{})

	go c.receiveDisco(sock, family == "ip6")
	return sock, nil
}

// parseUDPPacket is a basic parser for UDP packets that returns the source and
// destination addresses, and the payload. The returned payload is a sub-slice
// of the input buffer.
//
// It expects to be called with a buffer that contains the entire UDP packet,
// including the IP header, and one that has been filtered with the BPF
// programs above.
//
// If an error occurs, it will return the zero values for all return values.
func parseUDPPacket(buf []byte, isIPv6 bool) (src, dst netip.AddrPort, payload []byte) {
	// First, parse the IPv4 or IPv6 header to get to the UDP header. Since
	// we assume this was filtered with BPF, we know that there will be no
	// IPv6 extension headers.
	var (
		srcIP, dstIP netip.Addr
		udp          []byte
	)
	if isIPv6 {
		// Basic length check to ensure that we don't panic
		if len(buf) < ipv6.HeaderLen+udpHeaderSize {
			return
		}

		// Extract the source and destination addresses from the IPv6
		// header.
		srcIP, _ = netip.AddrFromSlice(buf[8:24])
		dstIP, _ = netip.AddrFromSlice(buf[24:40])

		// We know that the UDP packet starts immediately after the IPv6
		// packet.
		udp = buf[ipv6.HeaderLen:]
	} else {
		// This is an IPv4 packet; read the length field from the header.
		if len(buf) < ipv4.HeaderLen {
			return
		}
		udpOffset := int((buf[0] & 0x0F) << 2)
		if udpOffset+udpHeaderSize > len(buf) {
			return
		}

		// Parse the source and destination IPs.
		srcIP, _ = netip.AddrFromSlice(buf[12:16])
		dstIP, _ = netip.AddrFromSlice(buf[16:20])
		udp = buf[udpOffset:]
	}

	// Parse the ports
	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])

	// The payload starts after the UDP header.
	payload = udp[8:]
	return netip.AddrPortFrom(srcIP, srcPort), netip.AddrPortFrom(dstIP, dstPort), payload
}

// ethernetProtoIPv4 returns the constant unix.ETH_P_IP, in network byte order.
// packet(7) sockets require that the 'protocol' argument be in network byte
// order; see:
//
//	https://man7.org/linux/man-pages/man7/packet.7.html
//
// Instead of using htons at runtime, we can just hardcode the value here...
// but we also have a test that verifies that this is correct.
func ethernetProtoIPv4() int {
	if cpu.IsBigEndian {
		return 0x0800
	} else {
		return 0x0008
	}
}

// ethernetProtoIPv6 returns the constant unix.ETH_P_IPV6, and is otherwise the
// same as ethernetProtoIPv4.
func ethernetProtoIPv6() int {
	if cpu.IsBigEndian {
		return 0x86dd
	} else {
		return 0xdd86
	}
}

func (c *Conn) discoLogf(format string, args ...any) {
	// Enable debug logging if we're debugging raw disco reads or if the
	// magicsock component logs are on.
	if debugRawDiscoReads() {
		c.logf(format, args...)
	} else {
		c.dlogf(format, args...)
	}
}

func (c *Conn) receiveDisco(pc *socket.Conn, isIPV6 bool) {
	// Given that we're parsing raw packets, be extra careful and recover
	// from any panics in this function.
	//
	// If we didn't have a recover() here and panic'd, we'd take down the
	// entire process since this function is the top of a goroutine, and Go
	// will kill the process if a goroutine panics and it unwinds past the
	// top-level function.
	defer func() {
		if err := recover(); err != nil {
			c.logf("[unexpected] recovered from panic in receiveDisco(isIPv6=%v): %v", isIPV6, err)
		}
	}()

	ctx := context.Background()

	// Set up our loggers
	var family string
	if isIPV6 {
		family = "ip6"
	} else {
		family = "ip4"
	}
	var (
		prefix string      = "disco raw " + family + ": "
		logf   logger.Logf = logger.WithPrefix(c.logf, prefix)
		dlogf  logger.Logf = logger.WithPrefix(c.discoLogf, prefix)
	)

	var buf [1500]byte
	for {
		n, src, err := pc.Recvfrom(ctx, buf[:], 0)
		if debugRawDiscoReads() {
			logf("read from %s = (%v, %v)", printSockaddr(src), n, err)
		}
		if err != nil && (errors.Is(err, net.ErrClosed) || err.Error() == "use of closed file") {
			// EOF; no need to print an error
			return
		} else if err != nil {
			logf("reader failed: %v", err)
			return
		}

		srcAddr, dstAddr, payload := parseUDPPacket(buf[:n], family == "ip6")
		if payload == nil {
			// callee logged
			continue
		}

		dstPort := dstAddr.Port()
		if dstPort == 0 {
			logf("[unexpected] received packet for port 0")
		}

		var acceptPort uint16
		if isIPV6 {
			acceptPort = c.pconn6.Port()
		} else {
			acceptPort = c.pconn4.Port()
		}
		if acceptPort == 0 {
			// This should only typically happen if the receiving address family
			// was recently disabled.
			dlogf("[v1] dropping packet for port %d as acceptPort=0", dstPort)
			continue
		}

		// If the packet isn't destined for our local port, then we
		// should drop it since it might be for another Tailscale
		// process on the same machine, or NATed to a different machine
		// if this is a router, etc.
		//
		// We get the local port to compare against inside the receive
		// loop; we can't cache this beforehand because it can change
		// if/when we rebind.
		if dstPort != acceptPort {
			dlogf("[v1] dropping packet for port %d that isn't our local port", dstPort)
			continue
		}

		if isIPV6 {
			metricRecvDiscoPacketIPv6.Add(1)
		} else {
			metricRecvDiscoPacketIPv4.Add(1)
		}

		pt, isGeneveEncap := packetLooksLike(payload)
		if pt == packetLooksLikeDisco && !isGeneveEncap {
			// The BPF program matching on disco does not currently support
			// Geneve encapsulation. isGeneveEncap should not return true if
			// payload is disco.
			c.handleDiscoMessage(payload, epAddr{ap: srcAddr}, false, key.NodePublic{}, discoRXPathRawSocket)
		}
	}
}

// printSockaddr is a helper function to pretty-print various sockaddr types.
func printSockaddr(sa unix.Sockaddr) string {
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		addr := netip.AddrFrom4(sa.Addr)
		return netip.AddrPortFrom(addr, uint16(sa.Port)).String()
	case *unix.SockaddrInet6:
		addr := netip.AddrFrom16(sa.Addr)
		return netip.AddrPortFrom(addr, uint16(sa.Port)).String()
	case *unix.SockaddrLinklayer:
		hwaddr := sa.Addr[:sa.Halen]

		var buf strings.Builder
		fmt.Fprintf(&buf, "link(ty=0x%04x,if=%d):[", sa.Protocol, sa.Ifindex)
		for i, b := range hwaddr {
			if i > 0 {
				buf.WriteByte(':')
			}
			fmt.Fprintf(&buf, "%02x", b)
		}
		buf.WriteByte(']')
		return buf.String()
	default:
		return fmt.Sprintf("unknown(%T)", sa)
	}
}

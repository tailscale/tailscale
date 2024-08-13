// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
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
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

const (
	udpHeaderSize = 8

	// discoMinHeaderSize is the minimum size of the disco header in bytes.
	discoMinHeaderSize = len(disco.Magic) + 32 /* key length */ + disco.NonceLen
)

// Enable/disable using raw sockets to receive disco traffic.
var debugDisableRawDisco = envknob.RegisterBool("TS_DEBUG_DISABLE_RAW_DISCO")

// debugRawDiscoReads enables logging of raw disco reads.
var debugRawDiscoReads = envknob.RegisterBool("TS_DEBUG_RAW_DISCO")

// These are our BPF filters that we use for testing packets.
var (
	magicsockFilterV4 = []bpf.Instruction{
		// For raw sockets (with ETH_P_IP set), the BPF program
		// receives the entire IPv4 packet, but not the Ethernet
		// header.

		// Disco packets are so small they should never get
		// fragmented, and we don't want to handle reassembly.
		bpf.LoadAbsolute{Off: 6, Size: 2},
		// More Fragments bit set means this is part of a fragmented packet.
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x2000, SkipTrue: 7, SkipFalse: 0},
		// Non-zero fragment offset with MF=0 means this is the last
		// fragment of packet.
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6, SkipFalse: 0},

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
	if debugDisableRawDisco() {
		return nil, errors.New("raw disco listening disabled by debug flag")
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
		pkt packet.Parsed
	)
	for {
		n, _, err := sock.Recvfrom(ctx, buf[:], 0)
		if err != nil {
			sock.Close()
			return nil, fmt.Errorf("reading during raw disco self-test: %w", err)
		}

		if !decodeDiscoPacket(&pkt, c.discoLogf, buf[:n], family == "ip6") {
			continue
		}
		if payload := pkt.Payload(); !bytes.Equal(payload, testDiscoPacket) {
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

// decodeDiscoPacket decodes a disco packet from buf, using pkt as storage for
// the parsed packet. It returns true if the packet is a valid disco packet,
// and false otherwise.
//
// It will log the reason for the packet being invalid to logf; it is the
// caller's responsibility to control log verbosity.
func decodeDiscoPacket(pkt *packet.Parsed, logf logger.Logf, buf []byte, isIPv6 bool) bool {
	// Do a quick length check before we parse the packet, so we can drop
	// things that we know are too small.
	var minSize int
	if isIPv6 {
		minSize = ipv6.HeaderLen + udpHeaderSize + discoMinHeaderSize
	} else {
		minSize = ipv4.HeaderLen + udpHeaderSize + discoMinHeaderSize
	}
	if len(buf) < minSize {
		logf("decodeDiscoPacket: received packet too small to be a disco packet: %d bytes < %d", len(buf), minSize)
		return false
	}

	// Parse the packet.
	pkt.Decode(buf)

	// Verify that this is a UDP packet.
	if pkt.IPProto != ipproto.UDP {
		logf("decodeDiscoPacket: received non-UDP packet: %d", pkt.IPProto)
		return false
	}

	// Ensure that it's the right version of IP; given how we configure our
	// listening sockets, we shouldn't ever get the wrong one, but it's
	// best to confirm.
	var wantVersion uint8
	if isIPv6 {
		wantVersion = 6
	} else {
		wantVersion = 4
	}
	if pkt.IPVersion != wantVersion {
		logf("decodeDiscoPacket: received mismatched IP version %d (want %d)", pkt.IPVersion, wantVersion)
		return false
	}

	return true
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

	var (
		buf [1500]byte
		pkt packet.Parsed
	)
	for {
		n, src, err := pc.Recvfrom(ctx, buf[:], 0)
		if debugRawDiscoReads() {
			logf("read from %v = (%v, %v)", src, n, err)
		}
		if err != nil && (errors.Is(err, net.ErrClosed) || err.Error() == "use of closed file") {
			// EOF; no need to print an error
			return
		} else if err != nil {
			logf("reader failed: %v", err)
			return
		}

		if !decodeDiscoPacket(&pkt, dlogf, buf[:n], isIPV6) {
			// callee logged
			continue
		}

		dstPort := pkt.Dst.Port()
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

		c.handleDiscoMessage(pkt.Payload(), pkt.Src, key.NodePublic{}, discoRXPathRawSocket)
	}
}

// trySetSocketBuffer attempts to set SO_SNDBUFFORCE and SO_RECVBUFFORCE which
// can overcome the limit of net.core.{r,w}mem_max, but require CAP_NET_ADMIN.
// It falls back to the portable implementation if that fails, which may be
// silently capped to net.core.{r,w}mem_max.
func trySetSocketBuffer(pconn nettype.PacketConn, logf logger.Logf) {
	if c, ok := pconn.(*net.UDPConn); ok {
		var errRcv, errSnd error
		rc, err := c.SyscallConn()
		if err == nil {
			rc.Control(func(fd uintptr) {
				errRcv = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, socketBufferSize)
				if errRcv != nil {
					logf("magicsock: [warning] failed to force-set UDP read buffer size to %d: %v; using kernel default values (impacts throughput only)", socketBufferSize, errRcv)
				}
				errSnd = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, socketBufferSize)
				if errSnd != nil {
					logf("magicsock: [warning] failed to force-set UDP write buffer size to %d: %v; using kernel default values (impacts throughput only)", socketBufferSize, errSnd)
				}
			})
		}

		if err != nil || errRcv != nil || errSnd != nil {
			portableTrySetSocketBuffer(pconn, logf)
		}
	}
}

var controlMessageSize = -1 // bomb if used for allocation before init

func init() {
	// controlMessageSize is set to hold a UDP_GRO or UDP_SEGMENT control
	// message. These contain a single uint16 of data.
	controlMessageSize = unix.CmsgSpace(2)
}

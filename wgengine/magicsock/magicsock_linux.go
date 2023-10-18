// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
	"tailscale.com/net/netns"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

const (
	udpHeaderSize          = 8
	ipv6FragmentHeaderSize = 8
)

// Enable/disable using raw sockets to receive disco traffic.
var debugDisableRawDisco = envknob.RegisterBool("TS_DEBUG_DISABLE_RAW_DISCO")

// These are our BPF filters that we use for testing packets.
var (
	magicsockFilterV4 = []bpf.Instruction{
		// For raw UDPv4 sockets, BPF receives the entire IP packet to
		// inspect.

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
		// For raw UDPv6 sockets, BPF receives _only_ the UDP header onwards, not an entire IP packet.
		//
		//    https://stackoverflow.com/questions/24514333/using-bpf-with-sock-dgram-on-linux-machine
		//    https://blog.cloudflare.com/epbf_sockets_hop_distance/
		//
		// This is especially confusing because this *isn't* true for
		// IPv4; see the following code from the 'ping' utility that
		// corroborates this:
		//
		//    https://github.com/iputils/iputils/blob/1ab5fa/ping/ping.c#L1667-L1676
		//    https://github.com/iputils/iputils/blob/1ab5fa/ping/ping6_common.c#L933-L941

		// Compare with our magic number. Start by loading and
		// comparing the first 4 bytes of the UDP payload.
		bpf.LoadAbsolute{Off: udpHeaderSize, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: discoMagic1, SkipTrue: 0, SkipFalse: 3},

		// Compare the next 2 bytes
		bpf.LoadAbsolute{Off: udpHeaderSize + 4, Size: 2},
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
		network  string
		addr     string
		testAddr string
		prog     []bpf.Instruction
	)
	switch family {
	case "ip4":
		network = "ip4:17"
		addr = "0.0.0.0"
		testAddr = "127.0.0.1:1"
		prog = magicsockFilterV4
	case "ip6":
		network = "ip6:17"
		addr = "::"
		testAddr = "[::1]:1"
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

	// If all the above succeeds, we should be ready to receive. Just
	// out of paranoia, check that we do receive a well-formed disco
	// packet.
	tc, err := net.ListenPacket("udp", net.JoinHostPort(addr, "0"))
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("creating disco test socket: %w", err)
	}
	defer tc.Close()
	if _, err := tc.(*net.UDPConn).WriteToUDPAddrPort(testDiscoPacket, netip.MustParseAddrPort(testAddr)); err != nil {
		pc.Close()
		return nil, fmt.Errorf("writing disco test packet: %w", err)
	}
	pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var buf [1500]byte
	for {
		n, _, err := pc.ReadFrom(buf[:])
		if err != nil {
			pc.Close()
			return nil, fmt.Errorf("reading during raw disco self-test: %w", err)
		}
		if n < udpHeaderSize {
			continue
		}
		if !bytes.Equal(buf[udpHeaderSize:n], testDiscoPacket) {
			continue
		}
		break
	}
	pc.SetReadDeadline(time.Time{})

	go c.receiveDisco(pc, family == "ip6")
	return pc, nil
}

func (c *Conn) receiveDisco(pc net.PacketConn, isIPV6 bool) {
	var buf [1500]byte
	for {
		n, src, err := pc.ReadFrom(buf[:])
		if errors.Is(err, net.ErrClosed) {
			return
		} else if err != nil {
			c.logf("disco raw reader failed: %v", err)
			return
		}
		if n < udpHeaderSize {
			// Too small to be a valid UDP datagram, drop.
			continue
		}

		dstPort := binary.BigEndian.Uint16(buf[2:4])
		if dstPort == 0 {
			c.logf("[unexpected] disco raw: received packet for port 0")
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
			c.dlogf("[v1] disco raw: dropping packet for port %d as acceptPort=0", dstPort)
			continue
		}

		if dstPort != acceptPort {
			c.dlogf("[v1] disco raw: dropping packet for port %d", dstPort)
			continue
		}

		srcIP, ok := netip.AddrFromSlice(src.(*net.IPAddr).IP)
		if !ok {
			c.logf("[unexpected] PacketConn.ReadFrom returned not-an-IP %v in from", src)
			continue
		}
		srcPort := binary.BigEndian.Uint16(buf[:2])

		if srcIP.Is4() {
			metricRecvDiscoPacketIPv4.Add(1)
		} else {
			metricRecvDiscoPacketIPv6.Add(1)
		}

		c.handleDiscoMessage(buf[udpHeaderSize:n], netip.AddrPortFrom(srcIP, srcPort), key.NodePublic{}, discoRXPathRawSocket)
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

// tryEnableUDPOffload attempts to enable the UDP_GRO socket option on pconn,
// and returns two booleans indicating TX and RX UDP offload support.
func tryEnableUDPOffload(pconn nettype.PacketConn) (hasTX bool, hasRX bool) {
	if c, ok := pconn.(*net.UDPConn); ok {
		rc, err := c.SyscallConn()
		if err != nil {
			return
		}
		err = rc.Control(func(fd uintptr) {
			_, errSyscall := syscall.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
			hasTX = errSyscall == nil
			errSyscall = syscall.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
			hasRX = errSyscall == nil
		})
		if err != nil {
			return false, false
		}
	}
	return hasTX, hasRX
}

// getGSOSizeFromControl returns the GSO size found in control. If no GSO size
// is found or the len(control) < unix.SizeofCmsghdr, this function returns 0.
// A non-nil error will be returned if len(control) > unix.SizeofCmsghdr but
// its contents cannot be parsed as a socket control message.
func getGSOSizeFromControl(control []byte) (int, error) {
	var (
		hdr  unix.Cmsghdr
		data []byte
		rem  = control
		err  error
	)

	for len(rem) > unix.SizeofCmsghdr {
		hdr, data, rem, err = unix.ParseOneSocketControlMessage(control)
		if err != nil {
			return 0, fmt.Errorf("error parsing socket control message: %w", err)
		}
		if hdr.Level == unix.SOL_UDP && hdr.Type == unix.UDP_GRO && len(data) >= 2 {
			return int(binary.NativeEndian.Uint16(data[:2])), nil
		}
	}
	return 0, nil
}

// setGSOSizeInControl sets a socket control message in control containing
// gsoSize. If len(control) < controlMessageSize control's len will be set to 0.
func setGSOSizeInControl(control *[]byte, gsoSize uint16) {
	*control = (*control)[:0]
	if cap(*control) < int(unsafe.Sizeof(unix.Cmsghdr{})) {
		return
	}
	if cap(*control) < controlMessageSize {
		return
	}
	*control = (*control)[:cap(*control)]
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&(*control)[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16((*control)[unix.SizeofCmsghdr:], gsoSize)
	*control = (*control)[:unix.CmsgSpace(2)]
}

var controlMessageSize = -1 // bomb if used for allocation before init

func init() {
	// controlMessageSize is set to hold a UDP_GRO or UDP_SEGMENT control
	// message. These contain a single uint16 of data.
	controlMessageSize = unix.CmsgSpace(2)
}

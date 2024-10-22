// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tap

package tstun

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/syncs"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/util/multierr"
)

// TODO: this was randomly generated once. Maybe do it per process start? But
// then an upgraded tailscaled would be visible to devices behind it. So
// maybe instead make it a function of the tailscaled's wireguard public key?
// For now just hard code it.
var ourMAC = net.HardwareAddr{0x30, 0x2D, 0x66, 0xEC, 0x7A, 0x93}

func init() { createTAP = createTAPLinux }

func createTAPLinux(logf logger.Logf, tapName, bridgeName string) (tun.Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	dev, err := openDevice(logf, fd, tapName, bridgeName)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	return dev, nil
}

func openDevice(logf logger.Logf, fd int, tapName, bridgeName string) (tun.Device, error) {
	ifr, err := unix.NewIfreq(tapName)
	if err != nil {
		return nil, err
	}

	// Flags are stored as a uint16 in the ifreq union.
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return nil, err
	}

	if err := run("ip", "link", "set", "dev", tapName, "up"); err != nil {
		return nil, err
	}
	if bridgeName != "" {
		if err := run("brctl", "addif", bridgeName, tapName); err != nil {
			return nil, err
		}
	}

	return newTAPDevice(logf, fd, tapName)
}

type etherType [2]byte

var (
	etherTypeARP  = etherType{0x08, 0x06}
	etherTypeIPv4 = etherType{0x08, 0x00}
	etherTypeIPv6 = etherType{0x86, 0xDD}
)

const ipv4HeaderLen = 20

const (
	consumePacket = true
	passOnPacket  = false
)

// handleTAPFrame handles receiving a raw TAP ethernet frame and reports whether
// it's been handled (that is, whether it should NOT be passed to wireguard).
func (t *tapDevice) handleTAPFrame(ethBuf []byte) bool {

	if len(ethBuf) < ethernetFrameSize {
		// Corrupt. Ignore.
		if tapDebug {
			t.logf("tap: short TAP frame")
		}
		return consumePacket
	}
	ethDstMAC, ethSrcMAC := ethBuf[:6], ethBuf[6:12]
	_ = ethDstMAC
	et := etherType{ethBuf[12], ethBuf[13]}
	switch et {
	default:
		if tapDebug {
			t.logf("tap: ignoring etherType %v", et)
		}
		return consumePacket // filter out packet we should ignore
	case etherTypeIPv6:
		// TODO: support DHCPv6/ND/etc later. For now pass all to WireGuard.
		if tapDebug {
			t.logf("tap: ignoring IPv6 %v", et)
		}
		return passOnPacket
	case etherTypeIPv4:
		if len(ethBuf) < ethernetFrameSize+ipv4HeaderLen {
			// Bogus IPv4. Eat.
			if tapDebug {
				t.logf("tap: short ipv4")
			}
			return consumePacket
		}
		return t.handleDHCPRequest(ethBuf)
	case etherTypeARP:
		arpPacket := header.ARP(ethBuf[ethernetFrameSize:])
		if !arpPacket.IsValid() {
			// Bogus ARP. Eat.
			return consumePacket
		}
		switch arpPacket.Op() {
		case header.ARPRequest:
			req := arpPacket // better name at this point
			buf := make([]byte, header.EthernetMinimumSize+header.ARPSize)

			// Our ARP "Table" of one:
			var srcMAC [6]byte
			copy(srcMAC[:], ethSrcMAC)
			if old := t.destMAC(); old != srcMAC {
				t.destMACAtomic.Store(srcMAC)
			}

			eth := header.Ethernet(buf)
			eth.Encode(&header.EthernetFields{
				SrcAddr: tcpip.LinkAddress(ourMAC[:]),
				DstAddr: tcpip.LinkAddress(ethSrcMAC),
				Type:    0x0806, // arp
			})
			res := header.ARP(buf[header.EthernetMinimumSize:])
			res.SetIPv4OverEthernet()
			res.SetOp(header.ARPReply)

			// If the client's asking about their own IP, tell them it's
			// their own MAC. TODO(bradfitz): remove String allocs.
			if net.IP(req.ProtocolAddressTarget()).String() == t.clientIPv4.Load() {
				copy(res.HardwareAddressSender(), ethSrcMAC)
			} else {
				copy(res.HardwareAddressSender(), ourMAC[:])
			}

			copy(res.ProtocolAddressSender(), req.ProtocolAddressTarget())
			copy(res.HardwareAddressTarget(), req.HardwareAddressSender())
			copy(res.ProtocolAddressTarget(), req.ProtocolAddressSender())

			n, err := t.WriteEthernet(buf)
			if tapDebug {
				t.logf("tap: wrote ARP reply %v, %v", n, err)
			}
		}

		return consumePacket
	}
}

var (
	// routerIP is the IP address of the DHCP server.
	routerIP = net.ParseIP(tsaddr.TailscaleServiceIPString)
	// cgnatNetMask is the netmask of the 100.64.0.0/10 CGNAT range.
	cgnatNetMask = net.IPMask(net.ParseIP("255.192.0.0").To4())
)

// handleDHCPRequest handles receiving a raw TAP ethernet frame and reports whether
// it's been handled as a DHCP request. That is, it reports whether the frame should
// be ignored by the caller and not passed on.
func (t *tapDevice) handleDHCPRequest(ethBuf []byte) bool {
	const udpHeader = 8
	if len(ethBuf) < ethernetFrameSize+ipv4HeaderLen+udpHeader {
		if tapDebug {
			t.logf("tap: DHCP short")
		}
		return passOnPacket
	}
	ethDstMAC, ethSrcMAC := ethBuf[:6], ethBuf[6:12]

	if string(ethDstMAC) != "\xff\xff\xff\xff\xff\xff" {
		// Not a broadcast
		if tapDebug {
			t.logf("tap: dhcp no broadcast")
		}
		return passOnPacket
	}

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	p.Decode(ethBuf[ethernetFrameSize:])

	if p.IPProto != ipproto.UDP || p.Src.Port() != 68 || p.Dst.Port() != 67 {
		// Not a DHCP request.
		if tapDebug {
			t.logf("tap: DHCP wrong meta: %+v", p)
		}
		return passOnPacket
	}

	dp, err := dhcpv4.FromBytes(ethBuf[ethernetFrameSize+ipv4HeaderLen+udpHeader:])
	if err != nil {
		// Bogus. Trash it.
		if tapDebug {
			t.logf("tap: DHCP FromBytes bad")
		}
		return consumePacket
	}
	if tapDebug {
		t.logf("tap: DHCP request: %+v", dp)
	}
	switch dp.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		ips := t.clientIPv4.Load()
		if ips == "" {
			t.logf("tap: DHCP no client IP")
			return consumePacket
		}
		offer, err := dhcpv4.New(
			dhcpv4.WithReply(dp),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
			dhcpv4.WithRouter(routerIP), // the default route
			dhcpv4.WithDNS(routerIP),
			dhcpv4.WithServerIP(routerIP), // TODO: what is this?
			dhcpv4.WithOption(dhcpv4.OptServerIdentifier(routerIP)),
			dhcpv4.WithYourIP(net.ParseIP(ips)),
			dhcpv4.WithLeaseTime(3600), // hour works
			//dhcpv4.WithHwAddr(ethSrcMAC),
			dhcpv4.WithNetmask(cgnatNetMask),
			//dhcpv4.WithTransactionID(dp.TransactionID),
		)
		if err != nil {
			t.logf("error building DHCP offer: %v", err)
			return consumePacket
		}
		// Make a layer 2 packet to write out:
		pkt := packLayer2UDP(
			offer.ToBytes(),
			ourMAC, ethSrcMAC,
			netip.AddrPortFrom(netaddr.IPv4(100, 100, 100, 100), 67), // src
			netip.AddrPortFrom(netaddr.IPv4(255, 255, 255, 255), 68), // dst
		)

		n, err := t.WriteEthernet(pkt)
		if tapDebug {
			t.logf("tap: wrote DHCP OFFER %v, %v", n, err)
		}
	case dhcpv4.MessageTypeRequest:
		ips := t.clientIPv4.Load()
		if ips == "" {
			t.logf("tap: DHCP no client IP")
			return consumePacket
		}
		ack, err := dhcpv4.New(
			dhcpv4.WithReply(dp),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
			dhcpv4.WithDNS(routerIP),
			dhcpv4.WithRouter(routerIP),   // the default route
			dhcpv4.WithServerIP(routerIP), // TODO: what is this?
			dhcpv4.WithOption(dhcpv4.OptServerIdentifier(routerIP)),
			dhcpv4.WithYourIP(net.ParseIP(ips)), // Hello world
			dhcpv4.WithLeaseTime(3600),          // hour works
			dhcpv4.WithNetmask(cgnatNetMask),
		)
		if err != nil {
			t.logf("error building DHCP ack: %v", err)
			return consumePacket
		}
		// Make a layer 2 packet to write out:
		pkt := packLayer2UDP(
			ack.ToBytes(),
			ourMAC, ethSrcMAC,
			netip.AddrPortFrom(netaddr.IPv4(100, 100, 100, 100), 67), // src
			netip.AddrPortFrom(netaddr.IPv4(255, 255, 255, 255), 68), // dst
		)
		n, err := t.WriteEthernet(pkt)
		if tapDebug {
			t.logf("tap: wrote DHCP ACK %v, %v", n, err)
		}
	default:
		if tapDebug {
			t.logf("tap: unknown DHCP type")
		}
	}
	return consumePacket
}

func writeEthernetFrame(buf []byte, srcMAC, dstMAC net.HardwareAddr, proto tcpip.NetworkProtocolNumber) {
	// Ethernet header
	eth := header.Ethernet(buf)
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(srcMAC),
		DstAddr: tcpip.LinkAddress(dstMAC),
		Type:    proto,
	})
}

func packLayer2UDP(payload []byte, srcMAC, dstMAC net.HardwareAddr, src, dst netip.AddrPort) []byte {
	buf := make([]byte, header.EthernetMinimumSize+header.UDPMinimumSize+header.IPv4MinimumSize+len(payload))
	payloadStart := len(buf) - len(payload)
	copy(buf[payloadStart:], payload)
	srcB := src.Addr().As4()
	srcIP := tcpip.AddrFromSlice(srcB[:])
	dstB := dst.Addr().As4()
	dstIP := tcpip.AddrFromSlice(dstB[:])
	// Ethernet header
	writeEthernetFrame(buf, srcMAC, dstMAC, ipv4.ProtocolNumber)
	// IP header
	ipbuf := buf[header.EthernetMinimumSize:]
	ip := header.IPv4(ipbuf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(ipbuf)),
		TTL:         65,
		Protocol:    uint8(udp.ProtocolNumber),
		SrcAddr:     srcIP,
		DstAddr:     dstIP,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	// UDP header
	u := header.UDP(buf[header.EthernetMinimumSize+header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, srcIP, dstIP, uint16(len(u)))
	// Calculate the UDP checksum and set it.
	xsum = checksum.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))
	return []byte(buf)
}

func run(prog string, args ...string) error {
	cmd := exec.Command(prog, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error running %v: %v", cmd, err)
	}
	return nil
}

func (t *tapDevice) destMAC() [6]byte {
	return t.destMACAtomic.Load()
}

func newTAPDevice(logf logger.Logf, fd int, tapName string) (tun.Device, error) {
	err := unix.SetNonblock(fd, true)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "/dev/tap")
	d := &tapDevice{
		logf:   logf,
		file:   file,
		events: make(chan tun.Event),
		name:   tapName,
	}
	return d, nil
}

type tapDevice struct {
	file       *os.File
	logf       func(format string, args ...any)
	events     chan tun.Event
	name       string
	closeOnce  sync.Once
	clientIPv4 syncs.AtomicValue[string]

	destMACAtomic syncs.AtomicValue[[6]byte]
}

var _ setIPer = (*tapDevice)(nil)

func (t *tapDevice) SetIP(ipV4, ipV6TODO netip.Addr) error {
	t.clientIPv4.Store(ipV4.String())
	return nil
}

func (t *tapDevice) File() *os.File {
	return t.file
}

func (t *tapDevice) Name() (string, error) {
	return t.name, nil
}

// Read reads an IP packet from the TAP device. It strips the ethernet frame header.
func (t *tapDevice) Read(buffs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.ReadEthernet(buffs, sizes, offset)
	if err != nil || n == 0 {
		return n, err
	}
	// Strip the ethernet frame header.
	copy(buffs[0][offset:], buffs[0][offset+ethernetFrameSize:offset+sizes[0]])
	sizes[0] -= ethernetFrameSize
	return 1, nil
}

// ReadEthernet reads a raw ethernet frame from the TAP device.
func (t *tapDevice) ReadEthernet(buffs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.file.Read(buffs[0][offset:])
	if err != nil {
		return 0, err
	}
	if t.handleTAPFrame(buffs[0][offset : offset+n]) {
		return 0, nil
	}
	sizes[0] = n
	return 1, nil
}

// WriteEthernet writes a raw ethernet frame to the TAP device.
func (t *tapDevice) WriteEthernet(buf []byte) (int, error) {
	return t.file.Write(buf)
}

// ethBufPool holds a pool of bytes.Buffers for use in [tapDevice.Write].
var ethBufPool = syncs.Pool[*bytes.Buffer]{New: func() *bytes.Buffer { return new(bytes.Buffer) }}

// Write writes a raw IP packet to the TAP device. It adds the ethernet frame header.
func (t *tapDevice) Write(buffs [][]byte, offset int) (int, error) {
	errs := make([]error, 0)
	wrote := 0
	m := t.destMAC()
	dstMac := net.HardwareAddr(m[:])
	buf := ethBufPool.Get()
	defer ethBufPool.Put(buf)
	for _, buff := range buffs {
		buf.Reset()
		buf.Grow(header.EthernetMinimumSize + len(buff) - offset)

		var ebuf [14]byte
		switch buff[offset] >> 4 {
		case 4:
			writeEthernetFrame(ebuf[:], ourMAC, dstMac, ipv4.ProtocolNumber)
		case 6:
			writeEthernetFrame(ebuf[:], ourMAC, dstMac, ipv6.ProtocolNumber)
		default:
			continue
		}
		buf.Write(ebuf[:])
		buf.Write(buff[offset:])
		_, err := t.WriteEthernet(buf.Bytes())
		if err != nil {
			errs = append(errs, err)
		} else {
			wrote++
		}
	}
	return wrote, multierr.New(errs...)
}

func (t *tapDevice) MTU() (int, error) {
	ifr, err := unix.NewIfreq(t.name)
	if err != nil {
		return 0, err
	}
	if err := unix.IoctlIfreq(int(t.file.Fd()), unix.SIOCGIFMTU, ifr); err != nil {
		return 0, err
	}
	return int(ifr.Uint32()), nil
}

func (t *tapDevice) Events() <-chan tun.Event {
	return t.events
}

func (t *tapDevice) Close() error {
	var err error
	t.closeOnce.Do(func() {
		close(t.events)
		err = t.file.Close()
	})
	return err
}

func (t *tapDevice) BatchSize() int {
	return 1
}

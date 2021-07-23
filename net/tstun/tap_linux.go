// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstun

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"inet.af/netaddr"
	"inet.af/netstack/tcpip"
	"inet.af/netstack/tcpip/buffer"
	"inet.af/netstack/tcpip/header"
	"inet.af/netstack/tcpip/network/ipv4"
	"inet.af/netstack/tcpip/transport/udp"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

// TODO: this was randomly generated once. do it per process start? or is
// this good enough?
var ourMAC = net.HardwareAddr{0x30, 0x2D, 0x66, 0xEC, 0x7A, 0x93}

func init() { createTAP = createTAPLinux }

func createTAPLinux(tapName, bridgeName string) (fd int, err error) {
	var flags uint16 = syscall.IFF_TAP | syscall.IFF_NO_PI
	fd, err = syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return -1, err
	}
	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}
	copy(ifr.name[:], tapName)
	ifr.flags = flags
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		syscall.Close(fd)
		return -1, errno
	}
	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return -1, err
	}

	run("ip", "link", "set", "dev", tapName, "up")
	if bridgeName != "" {
		run("brctl", "addif", bridgeName, tapName)
	}
	return fd, nil
}

type etherType [2]byte

var (
	etherTypeARP  = etherType{0x08, 0x06}
	etherTypeIPv4 = etherType{0x08, 0x00}
	etherTypeIPv6 = etherType{0x86, 0xDD}
)

const ipv4HeaderLen = 20

// handleTAPFrame handles receiving a raw TAP ethernet frame and reports whether
// it's been handled (that is, whether it should NOT be passed to wireguard).
func (t *Wrapper) handleTAPFrame(ethBuf []byte) bool {
	if len(ethBuf) < ethernetFrameSize {
		// Corrupt. Ignore.
		t.logf("XXX short TAP frame")
		return true
	}
	ethDstMAC, ethSrcMAC := ethBuf[:6], ethBuf[6:12]
	_ = ethDstMAC
	et := etherType{ethBuf[12], ethBuf[13]}
	switch et {
	default:
		t.logf("XXX ignoring etherType %v", et)
		return true // what is this
	case etherTypeIPv6:
		// TODO: support DHCPv6/ND/etc later. For now pass all to WireGuard.
		t.logf("XXX ignoring IPv6 %v", et)
		return false
	case etherTypeIPv4:
		if len(ethBuf) < ethernetFrameSize+ipv4HeaderLen {
			// Bogus IPv4. Eat.
			t.logf("XXX short ipv4")
			return true
		}
		return t.handleDHCPRequest(ethBuf)
	case etherTypeARP:
		arpPacket := header.ARP(ethBuf[ethernetFrameSize:])
		if !arpPacket.IsValid() {
			// Bogus ARP. Eat.
			return true
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
			copy(res.HardwareAddressSender(), ourMAC[:])
			copy(res.ProtocolAddressSender(), req.ProtocolAddressTarget())
			copy(res.HardwareAddressTarget(), req.HardwareAddressSender())
			copy(res.ProtocolAddressTarget(), req.ProtocolAddressSender())

			n, err := t.tdev.Write(buf, 0)
			log.Printf("XXX wrote ARP reply %v, %v", n, err)
		}

		return true
	}
}

const theClientIP = "100.70.145.3" // TODO: make dynamic from netmap

const routerIP = "100.70.145.1" // must be in same netmask (currently hack at /24) as theClientIP

// handleDHCPRequest handles receiving a raw TAP ethernet frame and reports whether
// it's been handled as a DHCP request. That is, it reports whether the frame should
// be ignored by the caller and not passed on.
func (t *Wrapper) handleDHCPRequest(ethBuf []byte) bool {
	const udpHeader = 8
	if len(ethBuf) < ethernetFrameSize+ipv4HeaderLen+udpHeader {
		t.logf("XXX DHCP short")
		return false
	}
	ethDstMAC, ethSrcMAC := ethBuf[:6], ethBuf[6:12]

	if string(ethDstMAC) != "\xff\xff\xff\xff\xff\xff" {
		// Not a broadcast
		t.logf("XXX dhcp no broadcast")
		return false
	}

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	p.Decode(ethBuf[ethernetFrameSize:])

	if p.IPProto != ipproto.UDP || p.Src.Port() != 68 || p.Dst.Port() != 67 {
		// Not a DHCP request.
		t.logf("XXX DHCP wrong meta")
		return false
	}

	dp, err := dhcpv4.FromBytes(ethBuf[ethernetFrameSize+ipv4HeaderLen+udpHeader:])
	if err != nil {
		// Bogus. Trash it.
		t.logf("XXX DHCP FromBytes bad")
		return true
	}
	log.Printf("XXX DHCP request: %+v", dp)
	switch dp.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		offer, err := dhcpv4.New(
			dhcpv4.WithReply(dp),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
			dhcpv4.WithRouter(net.ParseIP(routerIP)), // the default route
			dhcpv4.WithDNS(net.ParseIP("100.100.100.100")),
			dhcpv4.WithGatewayIP(net.ParseIP("100.100.100.100").To4()), // why not
			//dhcpv4.WithServerIP(net.ParseIP("100.100.100.100")),  // why not
			dhcpv4.WithYourIP(net.ParseIP(theClientIP)),
			dhcpv4.WithLeaseTime(3600), // hour works
			//dhcpv4.WithHwAddr(ethSrcMAC),
			dhcpv4.WithNetmask(net.IPMask(net.ParseIP("255.255.255.0").To4())), // TODO: wrong
			//dhcpv4.WithTransactionID(dp.TransactionID),
		)
		if err != nil {
			t.logf("error building DHCP offer: %v", err)
			return true
		}
		// Wrap all the crap back up
		pkt := packLayer2UDP(
			offer.ToBytes(),
			ourMAC, ethSrcMAC,
			netaddr.IPPortFrom(netaddr.IPv4(100, 100, 100, 100), 67), // src
			netaddr.IPPortFrom(netaddr.MustParseIP(theClientIP), 68), // dst
		)
		n, err := t.tdev.Write(pkt, 0)
		log.Printf("XXX wrote DHCP OFFER %v, %v", n, err)
	case dhcpv4.MessageTypeRequest:
		ack, err := dhcpv4.New(
			dhcpv4.WithReply(dp),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
			dhcpv4.WithDNS(net.ParseIP("100.100.100.100")),
			dhcpv4.WithRouter(net.ParseIP(routerIP)),                   // actually the router
			dhcpv4.WithGatewayIP(net.ParseIP("100.100.100.100").To4()), // why not
			//dhcpv4.WithServerIP(net.ParseIP("100.100.100.100")),  // why not
			dhcpv4.WithYourIP(net.ParseIP(theClientIP)), // Hello world
			dhcpv4.WithLeaseTime(3600),                  // hour works
			dhcpv4.WithNetmask(net.IPMask(net.ParseIP("255.255.255.0").To4())),
		)
		if err != nil {
			t.logf("error building DHCP ack: %v", err)
			return true
		}
		// Wrap all the crap back up
		pkt := packLayer2UDP(
			ack.ToBytes(),
			ourMAC, ethSrcMAC,
			netaddr.IPPortFrom(netaddr.IPv4(100, 100, 100, 100), 67), // src
			netaddr.IPPortFrom(netaddr.MustParseIP(theClientIP), 68),
		)
		n, err := t.tdev.Write(pkt, 0)
		log.Printf("XXX wrote DHCP ACK %v, %v", n, err)
	default:
		t.logf("XXX unknown DHCP type")
	}
	return true
}

func packLayer2UDP(payload []byte, srcMAC, dstMAC net.HardwareAddr, src, dst netaddr.IPPort) []byte {
	buf := buffer.NewView(header.EthernetMinimumSize + header.UDPMinimumSize + header.IPv4MinimumSize + len(payload))
	payloadStart := len(buf) - len(payload)
	copy(buf[payloadStart:], payload)
	srcB := src.IP().As4()
	srcIP := tcpip.Address(srcB[:])
	dstB := dst.IP().As4()
	dstIP := tcpip.Address(dstB[:])
	// Ethernet header
	eth := header.Ethernet(buf)
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(srcMAC),
		DstAddr: tcpip.LinkAddress(dstMAC),
		Type:    ipv4.ProtocolNumber,
	})
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
	xsum = header.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))
	return []byte(buf)
}

func run(prog string, args ...string) {
	cmd := exec.Command(prog, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error running %v: %v", cmd, err)
	}
}

func (t *Wrapper) destMAC() [6]byte {
	mac, _ := t.destMACAtomic.Load().([6]byte)
	return mac
}

func (t *Wrapper) tapWrite(buf []byte, offset int) (int, error) {
	if offset < ethernetFrameSize {
		return 0, fmt.Errorf("[unexpected] weird offset %d for TAP write", offset)
	}
	eth := buf[offset-ethernetFrameSize:]
	dst := t.destMAC()
	copy(eth[:6], dst[:])
	copy(eth[6:12], ourMAC[:])
	et := etherTypeIPv4
	if buf[offset]>>4 == 6 {
		et = etherTypeIPv6
	}
	eth[12], eth[13] = et[0], et[1]
	t.logf("XXX tapWrite off=%v % x", offset, buf)
	return t.tdev.Write(buf, offset-ethernetFrameSize)
}

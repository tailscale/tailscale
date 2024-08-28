// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"tailscale.com/util/must"
)

const (
	ethType4 = layers.EthernetTypeIPv4
	ethType6 = layers.EthernetTypeIPv6
)

// TestPacketSideEffects tests that upon receiving certain
// packets, other packets and/or log statements are generated.
func TestPacketSideEffects(t *testing.T) {
	type netTest struct {
		name  string
		pkt   []byte // to send
		check func(*sideEffects) error
	}
	tests := []struct {
		netName string // name of the Server returned by setup
		setup   func() (*Server, error)
		tests   []netTest // to run against setup's Server
	}{
		{
			netName: "basic",
			setup:   newTwoNodesSameNetwork,
			tests: []netTest{
				{
					name: "drop-rando-ethertype",
					pkt:  mkEth(nodeMac(2), nodeMac(1), 0x4321, []byte("hello")),
					check: all(
						logSubstr("Dropping non-IP packet"),
					),
				},
				{
					name: "dst-mac-between-nodes",
					pkt:  mkEth(nodeMac(2), nodeMac(1), testingEthertype, []byte("hello")),
					check: all(
						numPkts(1),
						pktSubstr("SrcMAC=52:cc:cc:cc:cc:01 DstMAC=52:cc:cc:cc:cc:02 EthernetType=UnknownEthernetType"),
						pktSubstr("Unable to decode EthernetType 4660"),
					),
				},
				{
					name: "broadcast-mac",
					pkt:  mkEth(macBroadcast, nodeMac(1), testingEthertype, []byte("hello")),
					check: all(
						numPkts(1),
						pktSubstr("SrcMAC=52:cc:cc:cc:cc:01 DstMAC=ff:ff:ff:ff:ff:ff EthernetType=UnknownEthernetType"),
						pktSubstr("Unable to decode EthernetType 4660"),
					),
				},
				{
					name: "dns-request-v4",
					pkt:  mkDNSReq(4),
					check: all(
						numPkts(1),
						pktSubstr("Data=[52, 52, 0, 3] IP=52.52.0.3"),
					),
				},
				{
					name: "dns-request-v6",
					pkt:  mkDNSReq(6),
					check: all(
						numPkts(1),
						pktSubstr(" IP=2052::3 "),
					),
				},
			},
		},
		{
			netName: "v4",
			setup:   newTwoNodesSameV4Network,
			tests: []netTest{
				{
					name: "no-v6-reply-on-v4-only",
					pkt:  mkIPv6RouterSolicit(nodeMac(1), nodeLANIP6(1)),
					check: all(
						numPkts(0),
						logSubstr("dropping IPv6 packet on v4-only network"),
					),
				},
				// TODO(bradfitz): DHCP request + response
			},
		},
		{
			netName: "v6",
			setup: func() (*Server, error) {
				var c Config
				nw := c.AddNetwork("2000:52::1/64")
				c.AddNode(nw)
				c.AddNode(nw)
				return New(&c)
			},
			tests: []netTest{
				{
					name: "router-solicit",
					pkt:  mkIPv6RouterSolicit(nodeMac(1), nodeLANIP6(1)),
					check: all(
						logSubstr("sending IPv6 router advertisement to 52:cc:cc:cc:cc:01 from 52:ee:ee:ee:ee:01"),
						numPkts(1),
						pktSubstr("TypeCode=RouterAdvertisement"),
						pktSubstr("= ICMPv6RouterAdvertisement"),
						pktSubstr("SrcMAC=52:ee:ee:ee:ee:01 DstMAC=52:cc:cc:cc:cc:01 EthernetType=IPv6"),
					),
				},
				{
					name: "all-nodes",
					pkt:  mkAllNodesPing(nodeMac(1), nodeLANIP6(1)),
					check: all(
						numPkts(1),
						pktSubstr("SrcMAC=52:cc:cc:cc:cc:01 DstMAC=33:33:00:00:00:01"),
						pktSubstr("SrcIP=fe80::50cc:ccff:fecc:cc01 DstIP=ff02::1"),
						pktSubstr("TypeCode=EchoRequest"),
					),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.netName, func(t *testing.T) {
			s, err := tt.setup()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			for _, tt := range tt.tests {
				t.Run(tt.name, func(t *testing.T) {
					se := &sideEffects{}
					s.SetLoggerForTest(se.logf)
					for mac := range s.MACs() {
						s.RegisterSinkForTest(mac, func(eth []byte) {
							se.got = append(se.got, eth)
						})
					}

					if err := s.handleEthernetFrameFromVM(tt.pkt); err != nil {
						t.Fatal(err)
					}
					if tt.check != nil {
						if err := tt.check(se); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		})
	}

}

// mkEth encodes an ethernet frame with the given payload.
func mkEth(dst, src MAC, ethType layers.EthernetType, payload []byte) []byte {
	ret := make([]byte, 0, 14+len(payload))
	ret = append(ret, dst.HWAddr()...)
	ret = append(ret, src.HWAddr()...)
	ret = binary.BigEndian.AppendUint16(ret, uint16(ethType))
	return append(ret, payload...)
}

// mkLenPrefixed prepends a uint32 length to the given packet.
func mkLenPrefixed(pkt []byte) []byte {
	ret := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(ret, uint32(len(pkt)))
	copy(ret[4:], pkt)
	return ret
}

// mkIPv6RouterSolicit makes a IPv6 router solicitation packet
// ethernet frame.
func mkIPv6RouterSolicit(srcMAC MAC, srcIP netip.Addr) []byte {
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      srcIP.AsSlice(),
		DstIP:      net.ParseIP("ff02::2"), // all routers
	}
	icmp := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterSolicitation, 0),
	}

	ra := &layers.ICMPv6RouterSolicitation{
		Options: []layers.ICMPv6Option{{
			Type: layers.ICMPv6OptSourceAddress,
			Data: srcMAC.HWAddr(),
		}},
	}
	icmp.SetNetworkLayerForChecksum(ip)
	return mkEth(macAllRouters, srcMAC, ethType6, mkPacket(ip, icmp, ra))
}

func mkAllNodesPing(srcMAC MAC, srcIP netip.Addr) []byte {
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      srcIP.AsSlice(),
		DstIP:      net.ParseIP("ff02::1"), // all nodes
	}
	icmp := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}
	icmp.SetNetworkLayerForChecksum(ip)
	return mkEth(macAllNodes, srcMAC, ethType6, mkPacket(ip, icmp))
}

// mkDNSReq makes a DNS request to "control.tailscale" using the source IPs as
// defined in this test file.
//
// ipVer must be 4 or 6:
// If 4, it makes an A record request.
// If 6, it makes a AAAA record request.
//
// (Yes, this is technically unrelated (you can request A records over IPv6 or
// AAAA records over IPv4), but for test coverage reasons, assume that the ipVer
// of 6 means to also request an AAAA record.)
func mkDNSReq(ipVer int) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       nodeMac(1).HWAddr(),
		DstMAC:       routerMac(1).HWAddr(),
		EthernetType: layers.EthernetTypeIPv4,
	}
	if ipVer == 6 {
		eth.EthernetType = layers.EthernetTypeIPv6
	}

	var ip serializableNetworkLayer
	switch ipVer {
	case 4:
		ip = &layers.IPv4{
			Version:  4,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.ParseIP("192.168.0.101"),
			TTL:      64,
			DstIP:    FakeDNSIPv4().AsSlice(),
		}
	case 6:
		ip = &layers.IPv6{
			Version:    6,
			HopLimit:   64,
			NextHeader: layers.IPProtocolUDP,
			SrcIP:      net.ParseIP("2000:52::1"),
			DstIP:      FakeDNSIPv6().AsSlice(),
		}
	default:
		panic("bad ipVer")
	}

	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{
		ID: 789,
		Questions: []layers.DNSQuestion{{
			Name:  []byte("control.tailscale"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
	}
	if ipVer == 6 {
		dns.Questions[0].Type = layers.DNSTypeAAAA
	}
	return mkPacket(eth, ip, udp, dns)
}

// sideEffects gathers side effects as a result of sending a packet and tests
// whether those effects were as desired.
type sideEffects struct {
	logs []string
	got  [][]byte // ethernet packets received
}

func (se *sideEffects) logf(format string, args ...any) {
	se.logs = append(se.logs, fmt.Sprintf(format, args...))
}

// all aggregates several side effects checkers into one.
func all(checks ...func(*sideEffects) error) func(*sideEffects) error {
	return func(se *sideEffects) error {
		var errs []error
		for _, check := range checks {
			if err := check(se); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
}

// logSubstr returns a side effect checker func that checks
// whether a log statement was output containing substring sub.
func logSubstr(sub string) func(*sideEffects) error {
	return func(se *sideEffects) error {
		for _, log := range se.logs {
			if strings.Contains(log, sub) {
				return nil
			}
		}
		return fmt.Errorf("expected log substring %q not found; log statements were:\n%s", sub, strings.Join(se.logs, "\n"))
	}
}

// pkgSubstr returns a side effect checker func that checks whether an ethernet
// packet was received that, once decoded and stringified by gopacket, contains
// substring sub.
func pktSubstr(sub string) func(*sideEffects) error {
	return func(se *sideEffects) error {
		var pkts bytes.Buffer
		for i, pkt := range se.got {
			pkt := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Lazy)
			got := pkt.String()
			fmt.Fprintf(&pkts, "[pkt%d]:\n%s\n", i, got)
			if strings.Contains(got, sub) {
				return nil
			}
		}
		return fmt.Errorf("packet summary with substring %q not found; packets were:\n%s", sub, pkts.Bytes())
	}
}

// numPkts returns a side effect checker func that checks whether
// the received number of ethernet packets was the given number.
func numPkts(want int) func(*sideEffects) error {
	return func(se *sideEffects) error {
		if len(se.got) == want {
			return nil
		}
		var pkts bytes.Buffer
		for i, pkt := range se.got {
			pkt := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Lazy)
			got := pkt.String()
			fmt.Fprintf(&pkts, "[pkt%d]:\n%s\n", i, got)
		}
		return fmt.Errorf("got %d packets, want %d. packets were:\n%s", len(se.got), want, pkts.Bytes())
	}
}

func newTwoNodesSameNetwork() (*Server, error) {
	var c Config
	nw := c.AddNetwork("192.168.0.1/24", "2052::1/64")
	c.AddNode(nw)
	c.AddNode(nw)
	return New(&c)
}

func newTwoNodesSameV4Network() (*Server, error) {
	var c Config
	nw := c.AddNetwork("192.168.0.1/24")
	c.AddNode(nw)
	c.AddNode(nw)
	return New(&c)
}

// TestProtocolQEMU tests the protocol that qemu uses to connect to natlab's
// vnet. (uint32-length prefixed ethernet frames over a unix stream socket)
//
// This test makes two clients (as qemu would act) and has one send an ethernet
// packet to the other virtual LAN segment.
func TestProtocolQEMU(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("skipping on %s", runtime.GOOS)
	}
	s := must.Get(newTwoNodesSameNetwork())
	defer s.Close()
	s.SetLoggerForTest(t.Logf)

	td := t.TempDir()
	serverSock := filepath.Join(td, "vnet.sock")

	ln, err := net.Listen("unix", serverSock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var clientc [2]*net.UnixConn
	for i := range clientc {
		c, err := net.Dial("unix", serverSock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		clientc[i] = c.(*net.UnixConn)
	}

	for range clientc {
		conn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		go s.ServeUnixConn(conn.(*net.UnixConn), ProtocolQEMU)
	}

	sendBetweenClients(t, clientc, s, mkLenPrefixed)
}

// TestProtocolUnixDgram tests the protocol that macOS Virtualization.framework
// uses to connect to vnet. (unix datagram sockets)
//
// It is similar to TestProtocolQEMU but uses unix datagram sockets instead of
// streams.
func TestProtocolUnixDgram(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("skipping on %s", runtime.GOOS)
	}
	s := must.Get(newTwoNodesSameNetwork())
	defer s.Close()
	s.SetLoggerForTest(t.Logf)

	td := t.TempDir()
	serverSock := filepath.Join(td, "vnet.sock")
	serverAddr := must.Get(net.ResolveUnixAddr("unixgram", serverSock))

	var clientSock [2]string
	for i := range clientSock {
		clientSock[i] = filepath.Join(td, fmt.Sprintf("c%d.sock", i))
	}

	uc, err := net.ListenUnixgram("unixgram", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	go s.ServeUnixConn(uc, ProtocolUnixDGRAM)

	var clientc [2]*net.UnixConn
	for i := range clientc {
		c, err := net.DialUnix("unixgram",
			must.Get(net.ResolveUnixAddr("unixgram", clientSock[i])),
			serverAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		clientc[i] = c
	}

	sendBetweenClients(t, clientc, s, nil)
}

// sendBetweenClients is a test helper that tries to send an ethernet frame from
// one client to another.
//
// It first makes the two clients send a packet to a fictitious node 3, which
// forces their src MACs to be registered with a networkWriter internally so
// they can receive traffic.
//
// Normally a node starts up spamming DHCP + NDP but we don't get that as a side
// effect here, so this does it manually.
//
// It also then waits for them to be registered.
//
// wrap is an optional function that wraps the packet before sending it.
func sendBetweenClients(t testing.TB, clientc [2]*net.UnixConn, s *Server, wrap func([]byte) []byte) {
	t.Helper()
	if wrap == nil {
		wrap = func(b []byte) []byte { return b }
	}
	for i, c := range clientc {
		must.Get(c.Write(wrap(mkEth(nodeMac(3), nodeMac(i+1), testingEthertype, []byte("hello")))))
	}
	awaitCond(t, 5*time.Second, func() error {
		if n := s.RegisteredWritersForTest(); n != 2 {
			return fmt.Errorf("got %d registered writers, want 2", n)
		}
		return nil
	})

	// Now see if node1 can write to node2 and node2 receives it.
	pkt := wrap(mkEth(nodeMac(2), nodeMac(1), testingEthertype, []byte("test-msg")))
	t.Logf("writing % 02x", pkt)
	must.Get(clientc[0].Write(pkt))

	buf := make([]byte, len(pkt))
	clientc[1].SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientc[1].Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := buf[:n]
	if !bytes.Equal(got, pkt) {
		t.Errorf("bad packet\n got: % 02x\nwant: % 02x", got, pkt)
	}
}

func awaitCond(t testing.TB, timeout time.Duration, cond func() error) {
	t.Helper()
	t0 := time.Now()
	for {
		if err := cond(); err == nil {
			return
		}
		if time.Since(t0) > timeout {
			t.Fatalf("timed out after %v", timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

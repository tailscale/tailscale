// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// testMTU is the WAN MTU used by the tests below. It's the smallest MTU
// allowed for IPv6, the MTU of a Tailscale TUN, and thus the MTU of a
// tailnet-over-tailnet underlay: the case that motivated [Network.SetMTU].
const testMTU = 1280

// payloadOfIPLen returns a UDP payload sized so that the IPv4 packet carrying
// it is exactly ipLen bytes.
func payloadOfIPLen(ipLen int) gopacket.Payload {
	const ipv4AndUDPHeaderLen = 20 + 8
	return gopacket.Payload(make([]byte, ipLen-ipv4AndUDPHeaderLen))
}

// mkUDPToWAN makes an ethernet frame from node 1 to its router carrying a UDP
// packet to dst out on the simulated internet, with a payload sized so the IP
// packet is exactly ipLen bytes.
func mkUDPToWAN(dst netip.AddrPort, ipLen int) []byte {
	eth := &layers.Ethernet{
		SrcMAC: nodeMac(1).HWAddr(),
		DstMAC: routerMac(1).HWAddr(),
	}
	ip := mkIPLayer(layers.IPProtocolUDP, clientIPv4(1), dst.Addr())
	udp := &layers.UDP{SrcPort: 41641, DstPort: layers.UDPPort(dst.Port())}
	return mustPacket(eth, ip, udp, payloadOfIPLen(ipLen))
}

// wanPeer is net 2's WAN IP:port, which net 1 forwards towards.
var wanPeer = netip.MustParseAddrPort("2.2.2.2:41641")

// newMTUTestServer builds two networks, each with one node, where net 1 sends
// and net 2 receives the packets the MTU tests send. mtu1 and mtu2 are the
// respective WAN MTUs; 0 means unlimited.
//
// Net 2 uses a one-to-one NAT because, unlike the other NAT types, it has no
// stateful firewall: inbound packets are delivered without a prior outbound
// packet to open a mapping. That way a packet that fails to arrive did so
// because of the MTU and not for want of NAT state.
func newMTUTestServer(t *testing.T, mtu1, mtu2 int) *Server {
	t.Helper()
	var c Config
	nw1 := c.AddNetwork("2.1.1.1", "192.168.0.1/24", EasyNAT)
	nw2 := c.AddNetwork("2.2.2.2", "192.168.1.1/24", One2OneNAT)
	nw1.SetMTU(mtu1)
	nw2.SetMTU(mtu2)
	c.AddNode(nw1)
	c.AddNode(nw2)
	s, err := New(&c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	// Otherwise background RAs race the packet-count assertions.
	s.StopUnsolicitedRAsForTest()
	return s
}

// TestSetMTU tests that a network with an MTU forwards packets up to that size
// across its WAN link and silently drops the rest, in both directions.
func TestSetMTU(t *testing.T) {
	sizes := []struct {
		name     string
		ipLen    int
		wantDrop bool
	}{
		{"under-mtu", testMTU - 100, false},
		{"exactly-mtu", testMTU, false},
		{"one-over-mtu", testMTU + 1, true},
		// The case from tailscale/tailscale#20668: a 1280-byte tailnet TUN
		// packet plus WireGuard/UDP/IPv4 overhead, crossing an underlay that
		// is itself a 1280-MTU tailnet.
		{"nested-tailnet-packet", testMTU + 60, true},
	}
	// Constraining the sending vs. the receiving network exercises the egress
	// and ingress checks respectively. Either way the packet must not arrive.
	for _, dir := range []struct {
		name       string
		mtu1, mtu2 int
	}{
		{name: "egress", mtu1: testMTU},
		{name: "ingress", mtu2: testMTU},
	} {
		t.Run(dir.name, func(t *testing.T) {
			for _, tt := range sizes {
				t.Run(tt.name, func(t *testing.T) {
					s := newMTUTestServer(t, dir.mtu1, dir.mtu2)
					se := newSideEffects(s)

					if err := s.handleEthernetFrameFromVM(mkUDPToWAN(wanPeer, tt.ipLen)); err != nil {
						t.Fatal(err)
					}

					if got := anyLogContains(se, "exceeds WAN MTU"); got != tt.wantDrop {
						t.Errorf("IP length %d: dropped for MTU=%v, want %v; logs:\n%s",
							tt.ipLen, got, tt.wantDrop, strings.Join(se.logs, "\n"))
					}
					// The MTU drop must be what actually keeps the packet off
					// the far LAN, and an in-size packet must still get there.
					gotDelivered := len(se.got) > 0
					if wantDelivered := !tt.wantDrop; gotDelivered != wantDelivered {
						t.Errorf("IP length %d: delivered=%v, want %v; logs:\n%s",
							tt.ipLen, gotDelivered, wantDelivered, strings.Join(se.logs, "\n"))
					}
				})
			}
		})
	}
}

// TestSetMTUZeroMeansUnlimited tests that a network with no MTU set forwards
// arbitrarily large packets, so that SetMTU is opt-in and existing tests are
// unaffected.
func TestSetMTUZeroMeansUnlimited(t *testing.T) {
	s := newMTUTestServer(t, 0, 0)
	se := newSideEffects(s)

	if err := s.handleEthernetFrameFromVM(mkUDPToWAN(wanPeer, 9000)); err != nil {
		t.Fatal(err)
	}
	if anyLogContains(se, "exceeds WAN MTU") {
		t.Errorf("packet dropped for MTU on a network with no MTU set; logs:\n%s",
			strings.Join(se.logs, "\n"))
	}
	if len(se.got) == 0 {
		t.Errorf("9000-byte packet was not delivered; logs:\n%s", strings.Join(se.logs, "\n"))
	}
}

// TestSetMTUExemptsSameLAN tests that the MTU constrains only the router's WAN
// path: two nodes on one segment can exceed it, as on a real LAN whose own MTU
// is larger than the WAN link's.
func TestSetMTUExemptsSameLAN(t *testing.T) {
	var c Config
	nw := c.AddNetwork("2.1.1.1", "192.168.0.1/24", EasyNAT)
	nw.SetMTU(testMTU)
	c.AddNode(nw)
	c.AddNode(nw)
	s, err := New(&c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.StopUnsolicitedRAsForTest()
	se := newSideEffects(s)

	// Addressed to node 2's MAC, so the router never sees it.
	eth := &layers.Ethernet{
		SrcMAC: nodeMac(1).HWAddr(),
		DstMAC: nodeMac(2).HWAddr(),
	}
	ip := mkIPLayer(layers.IPProtocolUDP, clientIPv4(1), clientIPv4(2))
	udp := &layers.UDP{SrcPort: 41641, DstPort: 41641}
	frame := mustPacket(eth, ip, udp, payloadOfIPLen(testMTU+500))
	if err := s.handleEthernetFrameFromVM(frame); err != nil {
		t.Fatal(err)
	}

	if anyLogContains(se, "exceeds WAN MTU") {
		t.Errorf("intra-LAN packet was subject to the WAN MTU; logs:\n%s", strings.Join(se.logs, "\n"))
	}
	if len(se.got) == 0 {
		t.Errorf("intra-LAN oversize packet was not delivered; logs:\n%s", strings.Join(se.logs, "\n"))
	}
}

// anyLogContains reports whether any log line recorded in se contains sub.
func anyLogContains(se *sideEffects, sub string) bool {
	for _, log := range se.logs {
		if strings.Contains(log, sub) {
			return true
		}
	}
	return false
}

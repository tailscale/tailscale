// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"tailscale.com/disco"
	"tailscale.com/net/stun"
)

func TestPacketFaultDefaultPassthrough(t *testing.T) {
	n := new(network) // exercise the runtime type's literal zero value
	writes := new(atomic.Int64)
	pkt := packetFaultUDP4(t, "198.51.100.1:1234", "192.168.0.101:5678", []byte("hello"))

	n.conditionedWrite(packetFaultTestWriter(writes), pkt)

	if got := writes.Load(); got != 1 {
		t.Fatalf("writes = %d, want 1", got)
	}
}

func TestPacketFaultInitializedNoRulesInactive(t *testing.T) {
	engine := new(packetFaultEngine)
	if engine.active() {
		t.Fatal("new engine unexpectedly active")
	}
	engine.setRules(nil)
	if engine.active() {
		t.Fatal("empty rule set unexpectedly active")
	}
}

func TestPacketFaultOutboundRoutedIP(t *testing.T) {
	engine := new(packetFaultEngine)
	h := engine.setRules([]PacketFaultRule{{
		Direction: PacketDirectionOutbound,
		Protocol:  PacketProtocolUDP,
		DstPort:   41641,
	}})[0]
	eth := packetFaultUDP4(t, "192.168.0.101:1234", "198.51.100.1:41641", []byte("wireguard"))
	gp := gopacket.NewPacket(eth, layers.LayerTypeEthernet, gopacket.Lazy)
	ip4 := gp.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := gp.Layer(layers.LayerTypeUDP).(*layers.UDP)
	raw := append(append([]byte(nil), ip4.LayerContents()...), udp.LayerContents()...)
	if !engine.dropIP(PacketDirectionOutbound, raw) {
		t.Fatal("outbound routed IP packet was not dropped")
	}
	if h.Hits() != 1 {
		t.Fatalf("hits = %d; want 1", h.Hits())
	}
}

func TestPacketFaultProcessAdapterUsesRuntimeRules(t *testing.T) {
	_, cn, _ := newPacketFaultTestNetwork()
	h := cn.SetPacketFaultRules(PacketFaultRule{
		Direction: PacketDirectionOutbound,
		Protocol:  PacketProtocolUDP,
		Class:     PacketClassDisco,
	})[0]
	src := netip.MustParseAddrPort("192.168.0.101:41641")
	dst := netip.MustParseAddrPort("198.51.100.1:41641")
	discoPayload := append([]byte(disco.Magic), make([]byte, 32+disco.NonceLen)...)
	if !cn.ShouldDropUDPPacket(PacketDirectionOutbound, src, dst, discoPayload) {
		t.Fatal("process adapter did not apply runtime disco rule")
	}
	if cn.ShouldDropUDPPacket(PacketDirectionOutbound, src, dst, []byte("wireguard")) {
		t.Fatal("process adapter dropped non-disco WireGuard traffic")
	}
	if h.Hits() != 1 {
		t.Fatalf("hits = %d; want 1", h.Hits())
	}
}

func TestPacketFaultPreservesSetPacketLoss(t *testing.T) {
	n, cn, writes := newPacketFaultTestNetwork()
	cn.SetPacketLoss(1)
	n.lossRate = cn.lossRate // normally copied by New
	pkt := packetFaultUDP4(t, "198.51.100.1:1234", "192.168.0.101:5678", []byte("hello"))

	n.conditionedWrite(packetFaultTestWriter(writes), pkt)

	if got := writes.Load(); got != 0 {
		t.Fatalf("writes = %d, want 0", got)
	}
}

func TestPacketFaultExactOccurrence(t *testing.T) {
	n, cn, writes := newPacketFaultTestNetwork()
	h := cn.SetPacketFaultRules(PacketFaultRule{DropOccurrence: 3})[0]
	pkt := packetFaultUDP4(t, "198.51.100.1:1234", "192.168.0.101:5678", []byte("hello"))

	for range 5 {
		n.conditionedWrite(packetFaultTestWriter(writes), pkt)
	}

	if got := writes.Load(); got != 4 {
		t.Fatalf("writes = %d, want 4", got)
	}
	if got := h.Hits(); got != 5 {
		t.Fatalf("hits = %d, want 5", got)
	}
}

func TestPacketFaultOccurrenceControls(t *testing.T) {
	for _, tt := range []struct {
		name       string
		rule       PacketFaultRule
		iterations int
		wantWrites int64
	}{
		{"drop-first", PacketFaultRule{DropFirst: 2}, 5, 3},
		{"drop-every", PacketFaultRule{DropEvery: 2}, 5, 3},
		{"unconditional", PacketFaultRule{}, 3, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			n, cn, writes := newPacketFaultTestNetwork()
			cn.SetPacketFaultRules(tt.rule)
			pkt := packetFaultUDP4(t, "198.51.100.1:1234", "192.168.0.101:5678", []byte("hello"))
			for range tt.iterations {
				n.conditionedWrite(packetFaultTestWriter(writes), pkt)
			}
			if got := writes.Load(); got != tt.wantWrites {
				t.Fatalf("writes = %d, want %d", got, tt.wantWrites)
			}
		})
	}
}

func TestPacketFaultRuleMatching(t *testing.T) {
	discoPayload := append([]byte(disco.Magic), make([]byte, 32+disco.NonceLen)...)
	stunPayload := stun.Request(stun.TxID{1, 2, 3})

	t.Run("all-selectors-ipv4-udp-disco-inbound", func(t *testing.T) {
		n, cn, writes := newPacketFaultTestNetwork()
		match := packetFaultUDP4(t, "198.51.100.1:1234", "192.168.0.101:5678", discoPayload)
		cn.SetPacketFaultRules(PacketFaultRule{
			Direction: PacketDirectionInbound,
			Family:    PacketFamilyIPv4,
			Protocol:  PacketProtocolUDP,
			SrcAddr:   netip.MustParseAddr("198.51.100.1"),
			SrcPort:   1234,
			DstAddr:   netip.MustParseAddr("192.168.0.101"),
			DstPort:   5678,
			Class:     PacketClassDisco,
			Length:    packetFaultIPDatagramLength(t, match),
		})

		mismatches := [][]byte{
			packetFaultUDP4(t, "198.51.100.2:1234", "192.168.0.101:5678", discoPayload),
			packetFaultUDP4(t, "198.51.100.1:1235", "192.168.0.101:5678", discoPayload),
			packetFaultUDP4(t, "198.51.100.1:1234", "192.168.0.102:5678", discoPayload),
			packetFaultUDP4(t, "198.51.100.1:1234", "192.168.0.101:5679", discoPayload),
			packetFaultUDP4(t, "192.168.0.101:1234", "198.51.100.1:5678", discoPayload),
			packetFaultUDP6(t, "2001:db8::1:1234", "2001:db8:1::101:5678", discoPayload),
			packetFaultUDP4(t, "198.51.100.1:1234", "192.168.0.101:5678", []byte("not disco")),
			packetFaultUDP4(t, "198.51.100.1:1234", "192.168.0.101:5678", append(discoPayload, 1)),
		}
		for _, pkt := range mismatches {
			n.conditionedWrite(packetFaultTestWriter(writes), pkt)
		}
		n.conditionedWrite(packetFaultTestWriter(writes), match)

		if got, want := writes.Load(), int64(len(mismatches)); got != want {
			t.Fatalf("writes = %d, want %d (only matching packet should drop)", got, want)
		}
	})

	t.Run("ipv6-tcp-outbound-with-address-and-port-wildcards", func(t *testing.T) {
		n, cn, writes := newPacketFaultTestNetwork()
		pkt := packetFaultTCP6(t, "2001:db8:1::101:2222", "2001:db8:2::1:443", []byte("tcp"))
		cn.SetPacketFaultRules(PacketFaultRule{
			Direction: PacketDirectionOutbound,
			Family:    PacketFamilyIPv6,
			Protocol:  PacketProtocolTCP,
			SrcAddr:   netip.MustParseAddr("2001:db8:1::101"),
			DstPort:   443,
		})
		n.conditionedWrite(packetFaultTestWriter(writes), pkt)
		if got := writes.Load(); got != 0 {
			t.Fatalf("writes = %d, want 0", got)
		}
	})

	for _, tt := range []struct {
		name    string
		class   PacketClass
		payload []byte
	}{
		{"stun", PacketClassSTUN, stunPayload},
		{"non-disco-udp", PacketClassNonDiscoUDP, []byte("ordinary UDP")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			n, cn, writes := newPacketFaultTestNetwork()
			cn.SetPacketFaultRules(PacketFaultRule{Class: tt.class})
			n.conditionedWrite(packetFaultTestWriter(writes), packetFaultUDP4(t, "198.51.100.1:1", "192.168.0.101:2", tt.payload))
			if got := writes.Load(); got != 0 {
				t.Fatalf("writes = %d, want 0", got)
			}
		})
	}
}

func TestPacketFaultRuntimeUpdate(t *testing.T) {
	n, cn, writes := newPacketFaultTestNetwork()
	pkt := packetFaultUDP4(t, "198.51.100.1:1234", "192.168.0.101:5678", []byte("hello"))

	cn.SetPacketFaultRules(PacketFaultRule{DstPort: 5678})
	n.conditionedWrite(packetFaultTestWriter(writes), pkt)
	cn.SetPacketFaultRules(PacketFaultRule{DstPort: 9999})
	n.conditionedWrite(packetFaultTestWriter(writes), pkt)
	cn.SetPacketFaultRules()
	n.conditionedWrite(packetFaultTestWriter(writes), pkt)

	if got := writes.Load(); got != 2 {
		t.Fatalf("writes = %d, want 2", got)
	}
}

func TestPacketFaultHitNotification(t *testing.T) {
	n, cn, writes := newPacketFaultTestNetwork()
	h := cn.SetPacketFaultRules(PacketFaultRule{DropOccurrence: 2})[0]
	pkt := packetFaultUDP4(t, "198.51.100.1:1234", "192.168.0.101:5678", []byte("hello"))

	n.conditionedWrite(packetFaultTestWriter(writes), pkt)
	event := <-h.Events()
	if event.Occurrence != 1 || event.Dropped {
		t.Fatalf("first event = %+v, want occurrence 1 not dropped", event)
	}
	n.conditionedWrite(packetFaultTestWriter(writes), pkt)
	event = <-h.Events()
	if event.Occurrence != 2 || !event.Dropped {
		t.Fatalf("second event = %+v, want occurrence 2 dropped", event)
	}
}

func TestPacketFaultConcurrentUpdateAndWrite(t *testing.T) {
	n, cn, writes := newPacketFaultTestNetwork()
	pkt := packetFaultUDP4(t, "198.51.100.1:1234", "192.168.0.101:5678", []byte("hello"))
	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range iterations {
			if i%2 == 0 {
				cn.SetPacketFaultRules(PacketFaultRule{DropEvery: 2})
			} else {
				cn.SetPacketFaultRules()
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range iterations {
			n.conditionedWrite(packetFaultTestWriter(writes), pkt)
		}
	}()
	wg.Wait()

	// The exact number of writes depends on interleaving. This final update and
	// write prove the network remains usable after concurrent replacement.
	cn.SetPacketFaultRules()
	before := writes.Load()
	n.conditionedWrite(packetFaultTestWriter(writes), pkt)
	if got := writes.Load(); got != before+1 {
		t.Fatalf("final passthrough writes = %d, want %d", got, before+1)
	}
}

func newPacketFaultTestNetwork() (*network, *Network, *atomic.Int64) {
	engine := new(packetFaultEngine)
	n := &network{
		v4:           true,
		v6:           true,
		lanIP4:       netip.MustParsePrefix("192.168.0.1/24"),
		wanIP6:       netip.MustParsePrefix("2001:db8:1::1/64"),
		packetFaults: engine,
	}
	cn := &Network{network: n, packetFaults: engine}
	return n, cn, new(atomic.Int64)
}

func packetFaultTestWriter(writes *atomic.Int64) networkWriter {
	return networkWriter{writer: func(vmClient, []byte, int) { writes.Add(1) }}
}

func packetFaultUDP4(t testing.TB, src, dst string, payload []byte) []byte {
	t.Helper()
	return packetFaultUDP(t, netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), payload)
}

func packetFaultUDP6(t testing.TB, src, dst string, payload []byte) []byte {
	t.Helper()
	return packetFaultUDP(t, packetFaultMustParseIPv6AddrPort(src), packetFaultMustParseIPv6AddrPort(dst), payload)
}

func packetFaultMustParseIPv6AddrPort(s string) netip.AddrPort {
	i := stringsLastColon(s)
	return netip.MustParseAddrPort("[" + s[:i] + "]" + s[i:])
}

func stringsLastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

func packetFaultUDP(t testing.TB, src, dst netip.AddrPort, payload []byte) []byte {
	t.Helper()
	ip := mkIPLayer(layers.IPProtocolUDP, src.Addr(), dst.Addr())
	udp := &layers.UDP{SrcPort: layers.UDPPort(src.Port()), DstPort: layers.UDPPort(dst.Port())}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	ethType := layers.EthernetTypeIPv4
	if src.Addr().Is6() {
		ethType = layers.EthernetTypeIPv6
	}
	eth := &layers.Ethernet{SrcMAC: routerMac(1).HWAddr(), DstMAC: nodeMac(1).HWAddr(), EthernetType: ethType}
	return mustPacket(eth, ip, udp, gopacket.Payload(payload))
}

func packetFaultTCP6(t testing.TB, src, dst string, payload []byte) []byte {
	t.Helper()
	srcAP := packetFaultMustParseIPv6AddrPort(src)
	dstAP := packetFaultMustParseIPv6AddrPort(dst)
	ip := mkIPLayer(layers.IPProtocolTCP, srcAP.Addr(), dstAP.Addr())
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcAP.Port()), DstPort: layers.TCPPort(dstAP.Port()), SYN: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	eth := &layers.Ethernet{SrcMAC: routerMac(1).HWAddr(), DstMAC: nodeMac(1).HWAddr(), EthernetType: layers.EthernetTypeIPv6}
	return mustPacket(eth, ip, tcp, gopacket.Payload(payload))
}

func packetFaultIPDatagramLength(t testing.TB, pkt []byte) int {
	t.Helper()
	gp := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Lazy)
	if ip4, ok := gp.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		return int(ip4.Length)
	}
	if ip6, ok := gp.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		return 40 + int(ip6.Length)
	}
	t.Fatal("packet has no IP layer")
	return 0
}

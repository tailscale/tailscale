// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	wgtun "github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"go4.org/netipx"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/filter/filtertype"
)

type testConn25 struct {
	clientTransitIPForMagicIPFn             func(netip.Addr) (netip.Addr, error)
	connectorRealIPForTransitIPConnectionFn func(netip.Addr, netip.Addr) (netip.Addr, error)
}

func (tc *testConn25) ClientTransitIPForMagicIP(magicIP netip.Addr) (netip.Addr, error) {
	return tc.clientTransitIPForMagicIPFn(magicIP)
}

func (tc *testConn25) ConnectorRealIPForTransitIPConnection(srcIP netip.Addr, transitIP netip.Addr) (netip.Addr, error) {
	return tc.connectorRealIPForTransitIPConnectionFn(srcIP, transitIP)
}

func (tc *testConn25) ClientFlowCreated(transitIP netip.Addr) {}
func (tc *testConn25) ClientFlowRemoved(transitIP netip.Addr) {}

// testNet is the cast of addresses the datapath tests run against: a client,
// the Magic and Transit IPs it talks through, and the real server behind them,
// all in a single address family. It also carries the bits needed to
// synthesize a packet in that family.
type testNet struct {
	name      string
	ipVersion uint8

	clientSrcIP   netip.Addr // a client's Tailscale IP
	unknownSrcIP  netip.Addr // a Tailscale IP with no mapping on the connector
	magicIP       netip.Addr // a Magic IP mapped to transitIP
	unusedMagicIP netip.Addr // a Magic IP with no active Transit IP mapping
	transitIP     netip.Addr
	realIP        netip.Addr // the internet-facing address behind transitIP
}

var testNets = []testNet{
	{
		name:      "ipv4",
		ipVersion: 4,

		clientSrcIP:   netip.MustParseAddr("100.70.0.1"),
		unknownSrcIP:  netip.MustParseAddr("100.99.99.99"),
		magicIP:       netip.MustParseAddr("10.64.0.1"),
		unusedMagicIP: netip.MustParseAddr("10.64.0.2"),
		transitIP:     netip.MustParseAddr("169.254.0.1"),
		realIP:        netip.MustParseAddr("240.64.0.1"),
	},
	{
		name:      "ipv6",
		ipVersion: 6,

		clientSrcIP:   netip.MustParseAddr("fd7a:115c:a1e0::1"),
		unknownSrcIP:  netip.MustParseAddr("fd7a:115c:a1e0::9999"),
		magicIP:       netip.MustParseAddr("fd7a:115c:a1e0:a99c:100::1"),
		unusedMagicIP: netip.MustParseAddr("fd7a:115c:a1e0:a99c:100::2"),
		transitIP:     netip.MustParseAddr("fd7a:115c:a1e0:a99c:200::1"),
		realIP:        netip.MustParseAddr("2606:4700::6812:1a78"),
	},
}

func (tn testNet) udpPacket(src, dst netip.AddrPort) *packet.Parsed {
	var b []byte
	if tn.ipVersion == 6 {
		b = packet.Generate(packet.UDP6Header{
			IP6Header: packet.IP6Header{Src: src.Addr(), Dst: dst.Addr()},
			SrcPort:   src.Port(),
			DstPort:   dst.Port(),
		}, []byte("hello"))
	} else {
		b = packet.Generate(packet.UDP4Header{
			IP4Header: packet.IP4Header{Src: src.Addr(), Dst: dst.Addr()},
			SrcPort:   src.Port(),
			DstPort:   dst.Port(),
		}, []byte("hello"))
	}
	p := &packet.Parsed{}
	p.Decode(b)
	return p
}

func (tn testNet) checkPacket(t *testing.T, p *packet.Parsed, src, dst netip.AddrPort) {
	t.Helper()

	if got, want := p.Src, src; got != want {
		t.Errorf("unexpected packet src: got %v, want %v", got, want)
	}
	if got, want := p.Dst, dst; got != want {
		t.Errorf("unexpected packet dst: got %v, want %v", got, want)
	}
	if got, want := p.Buffer(), tn.udpPacket(src, dst).Buffer(); !bytes.Equal(got, want) {
		t.Errorf("unexpected packet bytes:\n got %+x\nwant %+x", got, want)
	}
}

func (tn testNet) checkICMPUnreachable(t *testing.T, got []byte, from, to netip.Addr, invoking *packet.Parsed) {
	t.Helper()

	var p packet.Parsed
	p.Decode(got)
	if !p.IsError() {
		t.Errorf("injected packet is not an ICMP error")
	}
	if got, want := p.Src.Addr(), from; got != want {
		t.Errorf("injected packet src: got %v, want %v", got, want)
	}
	if got, want := p.Dst.Addr(), to; got != want {
		t.Errorf("injected packet dst: got %v, want %v", got, want)
	}

	var want []byte
	if tn.ipVersion == 6 {
		// RFC 4443: as much of the invoking packet as fits
		// without exceeding the minimum IPv6 MTU. The test packets are
		// far below that, so the whole packet is quoted.
		want = packet.Generate(packet.ICMP6Header{
			IP6Header: packet.IP6Header{Src: from, Dst: to},
			Type:      packet.ICMP6Unreachable,
			Code:      packet.ICMP6AddressUnreachable,
		}, append(make([]byte, 4), invoking.Buffer()...))
	} else {
		// RFC 792: the IPv4 header, which is 20 bytes for the option-less
		// test packets, plus the first 64 bits of the datagram.
		want = packet.Generate(packet.ICMP4Header{
			IP4Header: packet.IP4Header{Src: from, Dst: to},
			Type:      packet.ICMP4Unreachable,
			Code:      packet.ICMP4HostUnreachable,
		}, append(make([]byte, 4), invoking.Buffer()[:20+8]...))
	}
	if !bytes.Equal(got, want) {
		t.Errorf("unexpected injected packet bytes:\n got %+x\nwant %+x", got, want)
	}
}

func (tn testNet) newClientDatapath(t *testing.T, throwMappingErr bool) *datapathHandler {
	t.Helper()

	mock := &testConn25{}
	mock.clientTransitIPForMagicIPFn = func(mip netip.Addr) (netip.Addr, error) {
		if throwMappingErr {
			return netip.Addr{}, errors.New("synthetic mapping error")
		}
		switch mip {
		case tn.magicIP:
			return tn.transitIP, nil
		case tn.unusedMagicIP:
			return netip.Addr{}, ErrUnmappedMagicIP
		}
		return netip.Addr{}, nil
	}
	return newDatapathHandler(mock, t.Logf)
}

func (tn testNet) newConnectorDatapath(t *testing.T, throwMappingErr bool) *datapathHandler {
	t.Helper()

	mock := &testConn25{}
	mock.connectorRealIPForTransitIPConnectionFn = func(src, tip netip.Addr) (netip.Addr, error) {
		if throwMappingErr {
			return netip.Addr{}, errors.New("synthetic mapping error")
		}
		if tip == tn.transitIP {
			if src == tn.clientSrcIP {
				return tn.realIP, nil
			}
			return netip.Addr{}, ErrUnmappedSrcAndTransitIP
		}
		return netip.Addr{}, nil
	}
	return newDatapathHandler(mock, t.Logf)
}

func TestHandlePacketFromTunDevice(t *testing.T) {
	const clientPort, serverPort = 1234, 80

	for _, tn := range testNets {
		tests := []struct {
			description            string
			src                    netip.AddrPort
			dst                    netip.AddrPort
			throwMappingErr        bool
			expectedSrc            netip.AddrPort
			expectedDst            netip.AddrPort
			expectedFilterResponse filter.Response
		}{
			{
				description:            "accept-and-nat-new-client-flow-mapped-magic-ip",
				src:                    netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				dst:                    netip.AddrPortFrom(tn.magicIP, serverPort),
				expectedSrc:            netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				expectedDst:            netip.AddrPortFrom(tn.transitIP, serverPort),
				expectedFilterResponse: filter.Accept,
			},
			{
				description:            "drop-unmapped-magic-ip",
				src:                    netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				dst:                    netip.AddrPortFrom(tn.unusedMagicIP, serverPort),
				expectedSrc:            netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				expectedDst:            netip.AddrPortFrom(tn.unusedMagicIP, serverPort),
				expectedFilterResponse: filter.Drop,
			},
			{
				description:            "accept-dont-nat-other-mapping-error",
				src:                    netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				dst:                    netip.AddrPortFrom(tn.magicIP, serverPort),
				throwMappingErr:        true,
				expectedSrc:            netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				expectedDst:            netip.AddrPortFrom(tn.magicIP, serverPort),
				expectedFilterResponse: filter.Accept,
			},
			{
				description:            "accept-dont-nat-uninteresting-client-side",
				src:                    netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				dst:                    netip.AddrPortFrom(tn.realIP, serverPort),
				expectedSrc:            netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				expectedDst:            netip.AddrPortFrom(tn.realIP, serverPort),
				expectedFilterResponse: filter.Accept,
			},
			{
				description:            "accept-dont-nat-uninteresting-connector-side",
				src:                    netip.AddrPortFrom(tn.realIP, serverPort),
				dst:                    netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				expectedSrc:            netip.AddrPortFrom(tn.realIP, serverPort),
				expectedDst:            netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				expectedFilterResponse: filter.Accept,
			},
		}

		t.Run(tn.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.description, func(t *testing.T) {
					dph := tn.newClientDatapath(t, tt.throwMappingErr)
					tun := newFakeTUN(t)
					p := tn.udpPacket(tt.src, tt.dst)

					if want, got := tt.expectedFilterResponse, dph.HandlePacketFromTunDevice(p, tun); want != got {
						t.Errorf("unexpected filter response: want %v, got %v", want, got)
					}
					tn.checkPacket(t, p, tt.expectedSrc, tt.expectedDst)
				})
			}
		})
	}
}

// TestUnmappedMagicIPICMPUnreachable verifies that a packet to a Magic IP with
// no active Transit IP mapping is dropped and an ICMP host-unreachable error is
// injected back toward the local host, sourced from the Magic IP and addressed
// to the original sender.
func TestUnmappedMagicIPICMPUnreachable(t *testing.T) {
	const clientPort, serverPort = 1234, 80

	for _, tn := range testNets {
		t.Run(tn.name, func(t *testing.T) {
			dph := tn.newClientDatapath(t, false)
			chtun, tun := newChannelTUN(t)

			// HandlePacketFromTunDevice blocks until the injected packet is
			// read, so drain the channel TUN concurrently.
			gotInboundPacketChan := make(chan []byte, 1)
			go func() { gotInboundPacketChan <- <-chtun.Inbound }()

			src := netip.AddrPortFrom(tn.clientSrcIP, clientPort)
			dst := netip.AddrPortFrom(tn.unusedMagicIP, serverPort)
			p := tn.udpPacket(src, dst)
			if got, want := dph.HandlePacketFromTunDevice(p, tun), filter.Drop; got != want {
				t.Fatalf("unexpected filter response: got %v, want %v", got, want)
			}
			// The dropped packet itself must be left untouched, since the
			// injected error quotes it.
			tn.checkPacket(t, p, src, dst)

			var injected []byte
			select {
			case injected = <-gotInboundPacketChan:
			case <-time.After(1 * time.Second):
				t.Fatal("timed out waiting for injected ICMP packet")
			}

			// The error should appear to come from the unreachable Magic IP,
			// addressed back to the original sender.
			tn.checkICMPUnreachable(t, injected, tn.unusedMagicIP, tn.clientSrcIP, p)
		})
	}
}

func TestHandlePacketFromWireGuard(t *testing.T) {
	const clientPort, serverPort = 1234, 80

	for _, tn := range testNets {
		tests := []struct {
			description            string
			src                    netip.AddrPort
			dst                    netip.AddrPort
			throwMappingErr        bool
			expectedSrc            netip.AddrPort
			expectedDst            netip.AddrPort
			expectedFilterResponse filter.Response
			expectedInjectedPkt    []byte
		}{
			{
				description:            "accept-and-nat-new-connector-flow-mapped-src-and-transit-ip",
				src:                    netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				dst:                    netip.AddrPortFrom(tn.transitIP, serverPort),
				expectedSrc:            netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				expectedDst:            netip.AddrPortFrom(tn.realIP, serverPort),
				expectedFilterResponse: filter.Accept,
			},
			{
				description:            "drop-unmapped-src-and-transit-ip",
				src:                    netip.AddrPortFrom(tn.unknownSrcIP, clientPort),
				dst:                    netip.AddrPortFrom(tn.transitIP, serverPort),
				expectedSrc:            netip.AddrPortFrom(tn.unknownSrcIP, clientPort),
				expectedDst:            netip.AddrPortFrom(tn.transitIP, serverPort),
				expectedFilterResponse: filter.Drop,
				expectedInjectedPkt: packet.Generate(packet.TailscaleRejectedHeader{
					IPSrc:  tn.transitIP,
					IPDst:  tn.unknownSrcIP,
					Proto:  ipproto.UDP,
					Src:    netip.AddrPortFrom(tn.unknownSrcIP, clientPort),
					Dst:    netip.AddrPortFrom(tn.transitIP, serverPort),
					Reason: packet.RejectedDueToUnknownAppConnectorTransitIP,
				}, nil),
			},
			{
				description:            "accept-dont-nat-other-mapping-error",
				src:                    netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				dst:                    netip.AddrPortFrom(tn.transitIP, serverPort),
				throwMappingErr:        true,
				expectedSrc:            netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				expectedDst:            netip.AddrPortFrom(tn.transitIP, serverPort),
				expectedFilterResponse: filter.Accept,
			},
			{
				description:            "accept-dont-nat-uninteresting-connector-side",
				src:                    netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				dst:                    netip.AddrPortFrom(tn.realIP, serverPort),
				expectedSrc:            netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				expectedDst:            netip.AddrPortFrom(tn.realIP, serverPort),
				expectedFilterResponse: filter.Accept,
			},
			{
				description:            "accept-dont-nat-uninteresting-client-side",
				src:                    netip.AddrPortFrom(tn.realIP, serverPort),
				dst:                    netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				expectedSrc:            netip.AddrPortFrom(tn.realIP, serverPort),
				expectedDst:            netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				expectedFilterResponse: filter.Accept,
			},
		}

		t.Run(tn.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.description, func(t *testing.T) {
					dph := tn.newConnectorDatapath(t, tt.throwMappingErr)
					tun := newFakeTUN(t)
					p := tn.udpPacket(tt.src, tt.dst)

					if want, got := tt.expectedFilterResponse, dph.HandlePacketFromWireGuard(p, tun); want != got {
						t.Errorf("unexpected filter response: want %v, got %v", want, got)
					}
					tn.checkPacket(t, p, tt.expectedSrc, tt.expectedDst)
					if tt.expectedInjectedPkt != nil {
						slab := make([]byte, (2*wgtun.ReadPacketSpacing)+(2*(1<<16-1)))
						packets := make([]wgtun.ReadPacket, 1)
						n, err := tun.Read(slab, packets)
						if err != nil {
							t.Errorf("error reading injected packet: %v", err)
						}
						if n != 1 {
							t.Errorf("expected to read 1 packet, got %d", n)
						}
						if want, got := tt.expectedInjectedPkt, slab[packets[0].Offset:packets[0].Offset+packets[0].Size]; !bytes.Equal(want, got) {
							t.Errorf("unexpected contents of injected packet: want %+x, got %+x", want, got)
						}
					}
				})
			}
		})
	}
}

func TestClientFlowCache(t *testing.T) {
	const clientPort, serverPort = 1234, 80

	for _, tn := range testNets {
		t.Run(tn.name, func(t *testing.T) {
			getTransitIPCalled := false

			mock := &testConn25{}
			mock.clientTransitIPForMagicIPFn = func(mip netip.Addr) (netip.Addr, error) {
				if getTransitIPCalled {
					t.Errorf("ClientGetTransitIPForMagicIP unexpectedly called more than once")
				}
				getTransitIPCalled = true
				return tn.transitIP, nil
			}
			dph := newDatapathHandler(mock, t.Logf)
			tun := newFakeTUN(t)

			newOutgoing := func() *packet.Parsed {
				return tn.udpPacket(
					netip.AddrPortFrom(tn.clientSrcIP, clientPort),
					netip.AddrPortFrom(tn.magicIP, serverPort),
				)
			}

			o1 := newOutgoing()
			if dph.HandlePacketFromTunDevice(o1, tun) != filter.Accept {
				t.Errorf("first call to HandlePacketFromTunDevice was not accepted")
			}
			tn.checkPacket(t, o1,
				netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				netip.AddrPortFrom(tn.transitIP, serverPort))
			// The second call should use the cache.
			o2 := newOutgoing()
			if dph.HandlePacketFromTunDevice(o2, tun) != filter.Accept {
				t.Errorf("second call to HandlePacketFromTunDevice was not accepted")
			}
			tn.checkPacket(t, o2,
				netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				netip.AddrPortFrom(tn.transitIP, serverPort))

			// Return traffic should have the Transit IP as the source,
			// and be SNATed to the Magic IP.
			incoming := tn.udpPacket(
				netip.AddrPortFrom(tn.transitIP, serverPort),
				netip.AddrPortFrom(tn.clientSrcIP, clientPort),
			)

			if dph.HandlePacketFromWireGuard(incoming, tun) != filter.Accept {
				t.Errorf("call to HandlePacketFromWireGuard was not accepted")
			}
			tn.checkPacket(t, incoming,
				netip.AddrPortFrom(tn.magicIP, serverPort),
				netip.AddrPortFrom(tn.clientSrcIP, clientPort))
		})
	}
}

func TestConnectorFlowCache(t *testing.T) {
	const clientPort, serverPort = 1234, 80

	for _, tn := range testNets {
		t.Run(tn.name, func(t *testing.T) {
			getRealIPCalled := false

			mock := &testConn25{}
			mock.connectorRealIPForTransitIPConnectionFn = func(src, tip netip.Addr) (netip.Addr, error) {
				if getRealIPCalled {
					t.Errorf("ConnectorRealIPForTransitIPConnection unexpectedly called more than once")
				}
				getRealIPCalled = true
				return tn.realIP, nil
			}
			dph := newDatapathHandler(mock, t.Logf)
			tun := newFakeTUN(t)

			newOutgoing := func() *packet.Parsed {
				return tn.udpPacket(
					netip.AddrPortFrom(tn.clientSrcIP, clientPort),
					netip.AddrPortFrom(tn.transitIP, serverPort),
				)
			}

			o1 := newOutgoing()
			if dph.HandlePacketFromWireGuard(o1, tun) != filter.Accept {
				t.Errorf("first call to HandlePacketFromWireGuard was not accepted")
			}
			tn.checkPacket(t, o1,
				netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				netip.AddrPortFrom(tn.realIP, serverPort))
			// The second call should use the cache.
			o2 := newOutgoing()
			if dph.HandlePacketFromWireGuard(o2, tun) != filter.Accept {
				t.Errorf("second call to HandlePacketFromWireGuard was not accepted")
			}
			tn.checkPacket(t, o2,
				netip.AddrPortFrom(tn.clientSrcIP, clientPort),
				netip.AddrPortFrom(tn.realIP, serverPort))

			// Return traffic should have the Real IP as the source,
			// and be SNATed to the Transit IP.
			incoming := tn.udpPacket(
				netip.AddrPortFrom(tn.realIP, serverPort),
				netip.AddrPortFrom(tn.clientSrcIP, clientPort),
			)

			if dph.HandlePacketFromTunDevice(incoming, tun) != filter.Accept {
				t.Errorf("call to HandlePacketFromTunDevice was not accepted")
			}
			tn.checkPacket(t, incoming,
				netip.AddrPortFrom(tn.transitIP, serverPort),
				netip.AddrPortFrom(tn.clientSrcIP, clientPort))
		})
	}
}

func newFakeTUN(t *testing.T) *tstun.Wrapper {
	t.Helper()
	return newWrappedTUN(t, tstun.NewFake())
}

// newChannelTUN is like newFakeTUN, but backed by a channel-based TUN device
// whose Inbound queue captures packets injected toward the local host (e.g. via
// InjectInboundCopy), so tests can observe them.
func newChannelTUN(t *testing.T) (*tuntest.ChannelTUN, *tstun.Wrapper) {
	t.Helper()

	chtun := tuntest.NewChannelTUN()
	return chtun, newWrappedTUN(t, chtun.TUN())
}

// newWrappedTUN wraps dev in a started [tstun.Wrapper]. We're not testing the
// filter, so it installs one that allows everything through, in both address
// families.
func newWrappedTUN(t *testing.T, dev wgtun.Device) *tstun.Wrapper {
	t.Helper()

	reg := new(usermetric.Registry)
	bus := eventbustest.NewBus(t)
	tun := tstun.Wrap(t.Logf, dev, reg, bus)

	protos := views.SliceOf([]ipproto.Proto{
		ipproto.TCP,
		ipproto.UDP,
		ipproto.ICMPv4,
		ipproto.ICMPv6,
	})
	allIPs := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}
	var sb netipx.IPSetBuilder
	dsts := make([]filtertype.NetPortRange, 0, len(allIPs))
	for _, pfx := range allIPs {
		sb.AddPrefix(pfx)
		dsts = append(dsts, filtertype.NetPortRange{Net: pfx, Ports: filtertype.AllPorts})
	}
	matches := []filter.Match{
		{
			IPProto: protos,
			Srcs:    allIPs,
			Dsts:    dsts,
		},
	}
	ipSet, _ := sb.IPSet()
	tun.SetFilter(filter.New(matches, nil, ipSet, ipSet, nil, t.Logf))

	tun.Start()
	t.Cleanup(func() { tun.Close() })
	return tun
}

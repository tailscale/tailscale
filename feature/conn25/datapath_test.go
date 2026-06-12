// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

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

func TestHandlePacketFromTunDevice(t *testing.T) {
	clientSrcIP := netip.MustParseAddr("100.70.0.1")
	magicIP := netip.MustParseAddr("10.64.0.1")
	unusedMagicIP := netip.MustParseAddr("10.64.0.2")
	transitIP := netip.MustParseAddr("169.254.0.1")
	realIP := netip.MustParseAddr("240.64.0.1")

	clientPort := uint16(1234)
	serverPort := uint16(80)

	tests := []struct {
		description            string
		p                      *packet.Parsed
		throwMappingErr        bool
		expectedSrc            netip.AddrPort
		expectedDst            netip.AddrPort
		expectedFilterResponse filter.Response
	}{
		{
			description: "accept-and-nat-new-client-flow-mapped-magic-ip",
			p: &packet.Parsed{
				Src: netip.AddrPortFrom(clientSrcIP, clientPort),
				Dst: netip.AddrPortFrom(magicIP, serverPort),
			},
			expectedSrc:            netip.AddrPortFrom(clientSrcIP, clientPort),
			expectedDst:            netip.AddrPortFrom(transitIP, serverPort),
			expectedFilterResponse: filter.Accept,
		},
		{
			description: "drop-unmapped-magic-ip",
			p: &packet.Parsed{
				Src: netip.AddrPortFrom(clientSrcIP, clientPort),
				Dst: netip.AddrPortFrom(unusedMagicIP, serverPort),
			},
			expectedSrc:            netip.AddrPortFrom(clientSrcIP, clientPort),
			expectedDst:            netip.AddrPortFrom(unusedMagicIP, serverPort),
			expectedFilterResponse: filter.Drop,
		},
		{
			description: "accept-dont-nat-other-mapping-error",
			p: &packet.Parsed{
				Src: netip.AddrPortFrom(clientSrcIP, clientPort),
				Dst: netip.AddrPortFrom(magicIP, serverPort),
			},
			throwMappingErr:        true,
			expectedSrc:            netip.AddrPortFrom(clientSrcIP, clientPort),
			expectedDst:            netip.AddrPortFrom(magicIP, serverPort),
			expectedFilterResponse: filter.Accept,
		},
		{
			description: "accept-dont-nat-uninteresting-client-side",
			p: &packet.Parsed{
				Src: netip.AddrPortFrom(clientSrcIP, clientPort),
				Dst: netip.AddrPortFrom(realIP, serverPort),
			},
			expectedSrc:            netip.AddrPortFrom(clientSrcIP, clientPort),
			expectedDst:            netip.AddrPortFrom(realIP, serverPort),
			expectedFilterResponse: filter.Accept,
		},
		{
			description: "accept-dont-nat-uninteresting-connector-side",
			p: &packet.Parsed{
				Src: netip.AddrPortFrom(realIP, serverPort),
				Dst: netip.AddrPortFrom(clientSrcIP, clientPort),
			},
			expectedSrc:            netip.AddrPortFrom(realIP, serverPort),
			expectedDst:            netip.AddrPortFrom(clientSrcIP, clientPort),
			expectedFilterResponse: filter.Accept,
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			mock := &testConn25{}
			mock.clientTransitIPForMagicIPFn = func(mip netip.Addr) (netip.Addr, error) {
				if tt.throwMappingErr {
					return netip.Addr{}, errors.New("synthetic mapping error")
				}
				if mip == magicIP {
					return transitIP, nil
				}
				if mip == unusedMagicIP {
					return netip.Addr{}, ErrUnmappedMagicIP
				}
				return netip.Addr{}, nil
			}
			dph := newDatapathHandler(mock, t.Logf)

			tt.p.IPProto = ipproto.UDP
			tt.p.IPVersion = 4
			tt.p.StuffForTesting(40)

			if want, got := tt.expectedFilterResponse, dph.HandlePacketFromTunDevice(tt.p); want != got {
				t.Errorf("unexpected filter response: want %v, got %v", want, got)
			}
			if want, got := tt.expectedSrc, tt.p.Src; want != got {
				t.Errorf("unexpected packet src: want %v, got %v", want, got)
			}
			if want, got := tt.expectedDst, tt.p.Dst; want != got {
				t.Errorf("unexpected packet dst: want %v, got %v", want, got)
			}
		})
	}
}

func newFakeTUN(t *testing.T) *tstun.Wrapper {
	t.Helper()

	// Create a TUN device and wrap it.
	fake := tstun.NewFake()
	reg := new(usermetric.Registry)
	bus := eventbustest.NewBus(t)
	tun := tstun.Wrap(t.Logf, fake, reg, bus)

	// Create a packet filter. We're not testing the filter, so just make
	// one that allows everything through.
	protos := views.SliceOf([]ipproto.Proto{
		ipproto.TCP,
		ipproto.UDP,
	})
	allIPs := netip.MustParsePrefix("0.0.0.0/0")
	matches := []filter.Match{
		{
			IPProto: protos,
			Srcs:    []netip.Prefix{allIPs},
			Dsts:    []filtertype.NetPortRange{{Net: allIPs, Ports: filtertype.AllPorts}},
		},
	}
	var sb netipx.IPSetBuilder
	sb.AddPrefix(allIPs)
	ipSet, _ := sb.IPSet()
	tun.SetFilter(filter.New(matches, nil, ipSet, ipSet, nil, t.Logf))

	// Start the TUN device.
	tun.Start()
	return tun
}

func TestHandlePacketFromWireGuard(t *testing.T) {
	clientSrcIP := netip.MustParseAddr("100.70.0.1")
	unknownSrcIP := netip.MustParseAddr("100.99.99.99")
	transitIP := netip.MustParseAddr("169.254.0.1")
	realIP := netip.MustParseAddr("240.64.0.1")

	clientPort := uint16(1234)
	serverPort := uint16(80)

	tests := []struct {
		description            string
		p                      *packet.Parsed
		throwMappingErr        bool
		expectedSrc            netip.AddrPort
		expectedDst            netip.AddrPort
		expectedFilterResponse filter.Response
		expectedInjectedPkt    []byte
	}{
		{
			description: "accept-and-nat-new-connector-flow-mapped-src-and-transit-ip",
			p: &packet.Parsed{
				Src: netip.AddrPortFrom(clientSrcIP, clientPort),
				Dst: netip.AddrPortFrom(transitIP, serverPort),
			},
			expectedSrc:            netip.AddrPortFrom(clientSrcIP, clientPort),
			expectedDst:            netip.AddrPortFrom(realIP, serverPort),
			expectedFilterResponse: filter.Accept,
		},
		{
			description: "drop-unmapped-src-and-transit-ip",
			p: &packet.Parsed{
				Src: netip.AddrPortFrom(unknownSrcIP, clientPort),
				Dst: netip.AddrPortFrom(transitIP, serverPort),
			},
			expectedSrc:            netip.AddrPortFrom(unknownSrcIP, clientPort),
			expectedDst:            netip.AddrPortFrom(transitIP, serverPort),
			expectedFilterResponse: filter.Drop,
			expectedInjectedPkt: packet.Generate(packet.TailscaleRejectedHeader{
				IPSrc:  transitIP,
				IPDst:  unknownSrcIP,
				Proto:  ipproto.UDP,
				Src:    netip.AddrPortFrom(unknownSrcIP, clientPort),
				Dst:    netip.AddrPortFrom(transitIP, serverPort),
				Reason: packet.RejectedDueToUnknownAppConnectorTransitIP,
			}, nil),
		},
		{
			description: "accept-dont-nat-other-mapping-error",
			p: &packet.Parsed{
				Src: netip.AddrPortFrom(clientSrcIP, clientPort),
				Dst: netip.AddrPortFrom(transitIP, serverPort),
			},
			throwMappingErr:        true,
			expectedSrc:            netip.AddrPortFrom(clientSrcIP, clientPort),
			expectedDst:            netip.AddrPortFrom(transitIP, serverPort),
			expectedFilterResponse: filter.Accept,
		},
		{
			description: "accept-dont-nat-uninteresting-connector-side",
			p: &packet.Parsed{
				Src: netip.AddrPortFrom(clientSrcIP, clientPort),
				Dst: netip.AddrPortFrom(realIP, serverPort),
			},
			expectedSrc:            netip.AddrPortFrom(clientSrcIP, clientPort),
			expectedDst:            netip.AddrPortFrom(realIP, serverPort),
			expectedFilterResponse: filter.Accept,
		},
		{
			description: "accept-dont-nat-uninteresting-client-side",
			p: &packet.Parsed{
				Src: netip.AddrPortFrom(realIP, serverPort),
				Dst: netip.AddrPortFrom(clientSrcIP, clientPort),
			},
			expectedSrc:            netip.AddrPortFrom(realIP, serverPort),
			expectedDst:            netip.AddrPortFrom(clientSrcIP, clientPort),
			expectedFilterResponse: filter.Accept,
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			mock := &testConn25{}
			mock.connectorRealIPForTransitIPConnectionFn = func(src, tip netip.Addr) (netip.Addr, error) {
				if tt.throwMappingErr {
					return netip.Addr{}, errors.New("synthetic mapping error")
				}
				if tip == transitIP {
					if src == clientSrcIP {
						return realIP, nil
					} else {
						return netip.Addr{}, ErrUnmappedSrcAndTransitIP
					}
				}
				return netip.Addr{}, nil
			}
			dph := newDatapathHandler(mock, t.Logf)
			tun := newFakeTUN(t)
			defer tun.Close()

			tt.p.IPProto = ipproto.UDP
			tt.p.IPVersion = 4
			tt.p.StuffForTesting(40)

			if want, got := tt.expectedFilterResponse, dph.HandlePacketFromWireGuard(tt.p, tun); want != got {
				t.Errorf("unexpected filter response: want %v, got %v", want, got)
			}
			if want, got := tt.expectedSrc, tt.p.Src; want != got {
				t.Errorf("unexpected packet src: want %v, got %v", want, got)
			}
			if want, got := tt.expectedDst, tt.p.Dst; want != got {
				t.Errorf("unexpected packet dst: want %v, got %v", want, got)
			}
			if tt.expectedInjectedPkt != nil {
				var buf [tstun.MaxPacketSize]byte
				bufs := [][]byte{buf[:]}
				sizes := []int{0}
				n, err := tun.Read(bufs, sizes, 0)
				if err != nil {
					t.Errorf("error reading injected packet: %v", err)
				}
				if n != 1 {
					t.Errorf("expected to read 1 packet, got %d", n)
				}
				if want, got := tt.expectedInjectedPkt, buf[:sizes[0]]; !bytes.Equal(want, got) {
					t.Errorf("unexpected contents of injected packet: want %+x, got %+x", want, got)

				}
			}
		})
	}
}

func TestClientFlowCache(t *testing.T) {
	getTransitIPCalled := false

	clientSrcIP := netip.MustParseAddr("100.70.0.1")
	magicIP := netip.MustParseAddr("10.64.0.1")
	transitIP := netip.MustParseAddr("169.254.0.1")

	clientPort := uint16(1234)
	serverPort := uint16(80)

	mock := &testConn25{}
	mock.clientTransitIPForMagicIPFn = func(mip netip.Addr) (netip.Addr, error) {
		if getTransitIPCalled {
			t.Errorf("ClientGetTransitIPForMagicIP unexpectedly called more than once")
		}
		getTransitIPCalled = true
		return transitIP, nil
	}
	dph := newDatapathHandler(mock, t.Logf)

	outgoing := packet.Parsed{
		IPProto:   ipproto.UDP,
		IPVersion: 4,
		Src:       netip.AddrPortFrom(clientSrcIP, clientPort),
		Dst:       netip.AddrPortFrom(magicIP, serverPort),
	}
	outgoing.StuffForTesting(40)

	o1 := outgoing
	if dph.HandlePacketFromTunDevice(&o1) != filter.Accept {
		t.Errorf("first call to HandlePacketFromTunDevice was not accepted")
	}
	if want, got := netip.AddrPortFrom(transitIP, serverPort), o1.Dst; want != got {
		t.Errorf("unexpected packet dst after first call: want %v, got %v", want, got)
	}
	// The second call should use the cache.
	o2 := outgoing
	if dph.HandlePacketFromTunDevice(&o2) != filter.Accept {
		t.Errorf("second call to HandlePacketFromTunDevice was not accepted")
	}
	if want, got := netip.AddrPortFrom(transitIP, serverPort), o2.Dst; want != got {
		t.Errorf("unexpected packet dst after second call: want %v, got %v", want, got)
	}

	// Return traffic should have the Transit IP as the source,
	// and be SNATed to the Magic IP.
	incoming := &packet.Parsed{
		IPProto:   ipproto.UDP,
		IPVersion: 4,
		Src:       netip.AddrPortFrom(transitIP, serverPort),
		Dst:       netip.AddrPortFrom(clientSrcIP, clientPort),
	}
	incoming.StuffForTesting(40)

	tun := newFakeTUN(t)
	defer tun.Close()

	if dph.HandlePacketFromWireGuard(incoming, tun) != filter.Accept {
		t.Errorf("call to HandlePacketFromWireGuard was not accepted")
	}
	if want, got := netip.AddrPortFrom(magicIP, serverPort), incoming.Src; want != got {
		t.Errorf("unexpected packet src after second call: want %v, got %v", want, got)
	}
}

func TestConnectorFlowCache(t *testing.T) {
	getRealIPCalled := false

	clientSrcIP := netip.MustParseAddr("100.70.0.1")
	transitIP := netip.MustParseAddr("169.254.0.1")
	realIP := netip.MustParseAddr("240.64.0.1")

	clientPort := uint16(1234)
	serverPort := uint16(80)

	mock := &testConn25{}
	mock.connectorRealIPForTransitIPConnectionFn = func(src, tip netip.Addr) (netip.Addr, error) {
		if getRealIPCalled {
			t.Errorf("ConnectorRealIPForTransitIPConnection unexpectedly called more than once")
		}
		getRealIPCalled = true
		return realIP, nil
	}
	dph := newDatapathHandler(mock, t.Logf)

	outgoing := packet.Parsed{
		IPProto:   ipproto.UDP,
		IPVersion: 4,
		Src:       netip.AddrPortFrom(clientSrcIP, clientPort),
		Dst:       netip.AddrPortFrom(transitIP, serverPort),
	}
	outgoing.StuffForTesting(40)

	tun := newFakeTUN(t)
	defer tun.Close()

	o1 := outgoing
	if dph.HandlePacketFromWireGuard(&o1, tun) != filter.Accept {
		t.Errorf("first call to HandlePacketFromWireGuard was not accepted")
	}
	if want, got := netip.AddrPortFrom(realIP, serverPort), o1.Dst; want != got {
		t.Errorf("unexpected packet dst after first call: want %v, got %v", want, got)
	}
	// The second call should use the cache.
	o2 := outgoing
	if dph.HandlePacketFromWireGuard(&o2, tun) != filter.Accept {
		t.Errorf("second call to HandlePacketFromWireGuard was not accepted")
	}
	if want, got := netip.AddrPortFrom(realIP, serverPort), o2.Dst; want != got {
		t.Errorf("unexpected packet dst after second call: want %v, got %v", want, got)
	}

	// Return traffic should have the Real IP as the source,
	// and be SNATed to the Transit IP.
	incoming := &packet.Parsed{
		IPProto:   ipproto.UDP,
		IPVersion: 4,
		Src:       netip.AddrPortFrom(realIP, serverPort),
		Dst:       netip.AddrPortFrom(clientSrcIP, clientPort),
	}
	incoming.StuffForTesting(40)

	if dph.HandlePacketFromTunDevice(incoming) != filter.Accept {
		t.Errorf("call to HandlePacketFromTunDevice was not accepted")
	}
	if want, got := netip.AddrPortFrom(transitIP, serverPort), incoming.Src; want != got {
		t.Errorf("unexpected packet src after second call: want %v, got %v", want, got)
	}
}

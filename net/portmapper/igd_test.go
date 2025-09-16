// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package portmapper

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"tailscale.com/net/netaddr"
	"tailscale.com/net/netmon"
	"tailscale.com/syncs"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/testenv"
)

// TestIGD is an IGD (Internet Gateway Device) for testing. It supports fake
// implementations of NAT-PMP, PCP, and/or UPnP to test clients against.
type TestIGD struct {
	upnpConn net.PacketConn // for UPnP discovery
	pxpConn  net.PacketConn // for NAT-PMP and/or PCP
	ts       *httptest.Server
	upnpHTTP syncs.AtomicValue[http.Handler]
	logf     logger.Logf
	closed   atomic.Bool

	// do* will log which packets are sent, but will not reply to unexpected packets.

	doPMP  bool
	doPCP  bool
	doUPnP bool

	mu       sync.Mutex // guards below
	counters igdCounters
}

// TestIGDOptions are options
type TestIGDOptions struct {
	PMP  bool
	PCP  bool
	UPnP bool // TODO: more options for 3 flavors of UPnP services
}

type igdCounters struct {
	numUPnPDiscoRecv     int32
	numUPnPOtherUDPRecv  int32
	numPMPRecv           int32
	numPCPRecv           int32
	numPCPDiscoRecv      int32
	numPCPMapRecv        int32
	numPCPOtherRecv      int32
	numPMPPublicAddrRecv int32
	numPMPBogusRecv      int32

	numFailedWrites  int32
	invalidPCPMapPkt int32
}

func NewTestIGD(tb testenv.TB, t TestIGDOptions) (*TestIGD, error) {
	logf := tstest.WhileTestRunningLogger(tb)
	d := &TestIGD{
		doPMP:  t.PMP,
		doPCP:  t.PCP,
		doUPnP: t.UPnP,
	}
	d.logf = func(msg string, args ...any) {
		// Don't log after the device has closed;
		// stray trailing logging angers testing.T.Logf.
		if d.closed.Load() {
			return
		}
		logf(msg, args...)
	}
	var err error
	if d.upnpConn, err = testListenUDP(); err != nil {
		return nil, err
	}
	if d.pxpConn, err = testListenUDP(); err != nil {
		d.upnpConn.Close()
		return nil, err
	}
	d.ts = httptest.NewServer(http.HandlerFunc(d.serveUPnPHTTP))
	go d.serveUPnPDiscovery()
	go d.servePxP()
	return d, nil
}

func testListenUDP() (net.PacketConn, error) {
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

func (d *TestIGD) TestPxPPort() uint16 {
	return uint16(d.pxpConn.LocalAddr().(*net.UDPAddr).Port)
}

func (d *TestIGD) TestUPnPPort() uint16 {
	return uint16(d.upnpConn.LocalAddr().(*net.UDPAddr).Port)
}

func testIPAndGateway() (gw, ip netip.Addr, ok bool) {
	return netaddr.IPv4(127, 0, 0, 1), netaddr.IPv4(1, 2, 3, 4), true
}

func (d *TestIGD) Close() error {
	d.closed.Store(true)
	d.ts.Close()
	d.upnpConn.Close()
	d.pxpConn.Close()
	return nil
}

func (d *TestIGD) inc(p *int32) {
	d.mu.Lock()
	defer d.mu.Unlock()
	(*p)++
}

func (d *TestIGD) stats() igdCounters {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.counters
}

func (d *TestIGD) SetUPnPHandler(h http.Handler) {
	d.upnpHTTP.Store(h)
}

func (d *TestIGD) serveUPnPHTTP(w http.ResponseWriter, r *http.Request) {
	if handler := d.upnpHTTP.Load(); handler != nil {
		handler.ServeHTTP(w, r)
		return
	}

	http.NotFound(w, r)
}

func (d *TestIGD) serveUPnPDiscovery() {
	buf := make([]byte, 1500)
	for {
		n, src, err := d.upnpConn.ReadFrom(buf)
		if err != nil {
			if !d.closed.Load() {
				d.logf("serveUPnP failed: %v", err)
			}
			return
		}
		pkt := buf[:n]
		if bytes.Equal(pkt, uPnPPacket) { // a super lazy "parse"
			d.inc(&d.counters.numUPnPDiscoRecv)
			resPkt := fmt.Appendf(nil, "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nEXT:\r\nSERVER: Tailscale-Test/1.0 UPnP/1.1 MiniUPnPd/2.2.1\r\nLOCATION: %s\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: 1627958564\r\nBOOTID.UPNP.ORG: 1627958564\r\nCONFIGID.UPNP.ORG: 1337\r\n\r\n", d.ts.URL+"/rootDesc.xml")
			if d.doUPnP {
				_, err = d.upnpConn.WriteTo(resPkt, src)
				if err != nil {
					d.inc(&d.counters.numFailedWrites)
				}
			}
		} else {
			d.inc(&d.counters.numUPnPOtherUDPRecv)
		}
	}
}

// servePxP serves NAT-PMP and PCP, which share a port number.
func (d *TestIGD) servePxP() {
	buf := make([]byte, 1500)
	for {
		n, a, err := d.pxpConn.ReadFrom(buf)
		if err != nil {
			if !d.closed.Load() {
				d.logf("servePxP failed: %v", err)
			}
			return
		}
		src := netaddr.Unmap(a.(*net.UDPAddr).AddrPort())
		if !src.IsValid() {
			panic("bogus addr")
		}
		pkt := buf[:n]
		if len(pkt) < 2 {
			continue
		}
		ver := pkt[0]
		switch ver {
		default:
			continue
		case pmpVersion:
			d.handlePMPQuery(pkt, src)
		case pcpVersion:
			d.handlePCPQuery(pkt, src)
		}
	}
}

func (d *TestIGD) handlePMPQuery(pkt []byte, src netip.AddrPort) {
	d.inc(&d.counters.numPMPRecv)
	if len(pkt) < 2 {
		return
	}
	op := pkt[1]
	switch op {
	case pmpOpMapPublicAddr:
		if len(pkt) != 2 {
			d.inc(&d.counters.numPMPBogusRecv)
			return
		}
		d.inc(&d.counters.numPMPPublicAddrRecv)

	}
	// TODO
}

func (d *TestIGD) handlePCPQuery(pkt []byte, src netip.AddrPort) {
	d.inc(&d.counters.numPCPRecv)
	if len(pkt) < 24 {
		return
	}
	op := pkt[1]
	pktSrcBytes := [16]byte{}
	copy(pktSrcBytes[:], pkt[8:24])
	pktSrc := netip.AddrFrom16(pktSrcBytes).Unmap()
	if pktSrc != src.Addr() {
		// TODO this error isn't fatal but should be rejected by server.
		// Since it's a test it's difficult to get them the same though.
		d.logf("mismatch of packet source and source IP: got %v, expected %v", pktSrc, src.Addr())
	}
	switch op {
	case pcpOpAnnounce:
		d.inc(&d.counters.numPCPDiscoRecv)
		if !d.doPCP {
			return
		}
		resp := buildPCPDiscoResponse(pkt)
		if _, err := d.pxpConn.WriteTo(resp, net.UDPAddrFromAddrPort(src)); err != nil {
			d.inc(&d.counters.numFailedWrites)
		}
	case pcpOpMap:
		if len(pkt) < 60 {
			d.logf("got too short packet for pcp op map: %v", pkt)
			d.inc(&d.counters.invalidPCPMapPkt)
			return
		}
		d.inc(&d.counters.numPCPMapRecv)
		if !d.doPCP {
			return
		}
		resp := buildPCPMapResponse(pkt)
		d.pxpConn.WriteTo(resp, net.UDPAddrFromAddrPort(src))
	default:
		// unknown op code, ignore it for now.
		d.inc(&d.counters.numPCPOtherRecv)
		return
	}
}

// newTestClient configures a new test client connected to igd for mapping updates.
// If bus == nil, a new empty event bus is constructed that is cleaned up when t exits.
// A cleanup for the resulting client is also added to t.
func newTestClient(t *testing.T, igd *TestIGD, bus *eventbus.Bus) *Client {
	if bus == nil {
		bus = eventbus.New()
		t.Log("Created empty event bus for test client")
		t.Cleanup(bus.Close)
	}
	var c *Client
	c = NewClient(Config{
		Logf:     tstest.WhileTestRunningLogger(t),
		NetMon:   netmon.NewStatic(),
		EventBus: bus,
		OnChange: func() { // TODO(creachadair): Remove.
			t.Logf("port map changed")
			t.Logf("have mapping: %v", c.HaveMapping())
		},
	})
	c.testPxPPort = igd.TestPxPPort()
	c.testUPnPPort = igd.TestUPnPPort()
	c.netMon = netmon.NewStatic()
	c.SetGatewayLookupFunc(testIPAndGateway)
	t.Cleanup(func() { c.Close() })
	return c
}

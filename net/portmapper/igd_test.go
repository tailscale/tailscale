// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmapper

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"

	"inet.af/netaddr"
)

// TestIGD is an IGD (Intenet Gateway Device) for testing. It supports fake
// implementations of NAT-PMP, PCP, and/or UPnP to test clients against.
type TestIGD struct {
	upnpConn net.PacketConn // for UPnP discovery
	pxpConn  net.PacketConn // for NAT-PMP and/or PCP
	ts       *httptest.Server

	doPMP  bool
	doPCP  bool
	doUPnP bool // TODO: more options for 3 flavors of UPnP services

	mu       sync.Mutex // guards below
	counters igdCounters
}

type igdCounters struct {
	numUPnPDiscoRecv     int32
	numUPnPOtherUDPRecv  int32
	numUPnPHTTPRecv      int32
	numPMPRecv           int32
	numPMPDiscoRecv      int32
	numPCPRecv           int32
	numPCPDiscoRecv      int32
	numPMPPublicAddrRecv int32
	numPMPBogusRecv      int32
}

func NewTestIGD() (*TestIGD, error) {
	d := &TestIGD{
		doPMP:  true,
		doPCP:  true,
		doUPnP: true,
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

func (d *TestIGD) Close() error {
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

func (d *TestIGD) serveUPnPHTTP(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r) // TODO
}

func (d *TestIGD) serveUPnPDiscovery() {
	buf := make([]byte, 1500)
	for {
		n, src, err := d.upnpConn.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		if bytes.Equal(pkt, uPnPPacket) { // a super lazy "parse"
			d.inc(&d.counters.numUPnPDiscoRecv)
			resPkt := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nEXT:\r\nSERVER: Tailscale-Test/1.0 UPnP/1.1 MiniUPnPd/2.2.1\r\nLOCATION: %s\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: 1627958564\r\nBOOTID.UPNP.ORG: 1627958564\r\nCONFIGID.UPNP.ORG: 1337\r\n\r\n", d.ts.URL+"/rootDesc.xml"))
			d.upnpConn.WriteTo(resPkt, src)
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
			return
		}
		ua := a.(*net.UDPAddr)
		src, ok := netaddr.FromStdAddr(ua.IP, ua.Port, ua.Zone)
		if !ok {
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

func (d *TestIGD) handlePMPQuery(pkt []byte, src netaddr.IPPort) {
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

func (d *TestIGD) handlePCPQuery(pkt []byte, src netaddr.IPPort) {
	d.inc(&d.counters.numPCPRecv)
	// TODO
}

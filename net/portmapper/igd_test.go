// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmapper

import (
	"net"
	"net/http"
	"net/http/httptest"
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
}

func NewTestIGD() (*TestIGD, error) {
	d := &TestIGD{
		doPMP:  true,
		doPCP:  true,
		doUPnP: true,
	}
	var err error
	if d.upnpConn, err = net.ListenPacket("udp", "127.0.0.1:1900"); err != nil {
		return nil, err
	}
	if d.pxpConn, err = net.ListenPacket("udp", "127.0.0.1:5351"); err != nil {
		return nil, err
	}
	d.ts = httptest.NewServer(http.HandlerFunc(d.serveUPnPHTTP))
	go d.serveUPnPDiscovery()
	go d.servePxP()
	return d, nil
}

func (d *TestIGD) Close() error {
	d.ts.Close()
	d.upnpConn.Close()
	d.pxpConn.Close()
	return nil
}

func (d *TestIGD) serveUPnPHTTP(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r) // TODO
}

func (d *TestIGD) serveUPnPDiscovery() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := d.upnpConn.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		_, _ = pkt, addr // TODO
	}
}

// servePxP serves NAT-PMP and PCP, which share a port number.
func (d *TestIGD) servePxP() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := d.pxpConn.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		_, _ = pkt, addr // TODO
	}
}

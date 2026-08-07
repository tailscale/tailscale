// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve && !ts_omit_usermetrics

package ipnlocal

import (
	"expvar"
	"io"
	"net"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/util/usermetric"
)

func counterValue(m *usermetric.MultiLabelMap[serveLabels], svc string) int64 {
	v, _ := m.Get(serveLabels{Service: svc}).(*expvar.Int)
	if v == nil {
		return -1
	}
	return v.Value()
}

func TestServiceMeteredConn(t *testing.T) {
	b := newTestBackend(t)

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	wrapped := b.meteredConnForService(serverSide, tailcfg.ServiceName("svc:foo"))

	const inboundPayload = "hello from client"
	writeDone := make(chan struct{})
	go func() {
		clientSide.Write([]byte(inboundPayload))
		close(writeDone)
	}()
	buf := make([]byte, len(inboundPayload))
	if _, err := io.ReadFull(wrapped, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	<-writeDone
	if got := counterValue(b.metrics.serveBytesInbound, "svc:foo"); got != int64(len(inboundPayload)) {
		t.Errorf("inbound = %d; want %d", got, len(inboundPayload))
	}

	// Deliberately a different length than inboundPayload so a backwards
	// inbound/outbound wiring can't pass.
	const outboundPayload = "hello from the server side"
	writeDone = make(chan struct{})
	go func() {
		wrapped.Write([]byte(outboundPayload))
		close(writeDone)
	}()
	buf = make([]byte, len(outboundPayload))
	if _, err := io.ReadFull(clientSide, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	<-writeDone
	if got := counterValue(b.metrics.serveBytesOutbound, "svc:foo"); got != int64(len(outboundPayload)) {
		t.Errorf("outbound = %d; want %d", got, len(outboundPayload))
	}
}

func TestServiceMeteredConnLabelKeepsPrefix(t *testing.T) {
	b := newTestBackend(t)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	wrapped := b.meteredConnForService(c1, tailcfg.ServiceName("svc:my-app"))
	go c2.Write([]byte("x"))
	io.ReadFull(wrapped, make([]byte, 1))
	if v := counterValue(b.metrics.serveBytesInbound, "svc:my-app"); v != 1 {
		t.Errorf("inbound for service=\"svc:my-app\" = %d; want 1", v)
	}
	if v := counterValue(b.metrics.serveBytesInbound, "my-app"); v != -1 {
		t.Errorf("counter unexpectedly present under prefix-stripped name; got %d", v)
	}
}

func TestServeMetricSeriesCreatedFromConfig(t *testing.T) {
	b := newTestBackend(t)
	const (
		serveService = tailcfg.ServiceName("svc:serve")
		tunService   = tailcfg.ServiceName("svc:tun")
	)
	b.mu.Lock()
	b.serveConfig = (&ipn.ServeConfig{
		Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
			serveService: {},
			tunService:   {Tun: true},
		},
	}).View()
	b.ensureServeMetricSeriesLocked()
	b.mu.Unlock()

	if got := counterValue(b.metrics.serveBytesInbound, serveService.String()); got != 0 {
		t.Errorf("initial inbound = %d; want zero-valued series", got)
	}
	if got := counterValue(b.metrics.serveBytesOutbound, serveService.String()); got != 0 {
		t.Errorf("initial outbound = %d; want zero-valued series", got)
	}
	if got := counterValue(b.metrics.serveBytesInbound, tunService.String()); got != -1 {
		t.Errorf("Serve counter for TUN Service = %d; want absent", got)
	}
	if got := counterValue(b.metrics.serveBytesOutbound, tunService.String()); got != -1 {
		t.Errorf("Serve counter for TUN Service = %d; want absent", got)
	}
}

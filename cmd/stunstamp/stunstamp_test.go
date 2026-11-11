// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func testTCPDial(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var port lportForTCPConn // let the kernel select an available local port
	c, err := tcpDial(t.Context(), &port, netip.MustParseAddrPort(ln.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestTCPDial(t *testing.T) {
	if c := testTCPDial(t); c.LocalAddr().(*net.TCPAddr).Port == 0 {
		t.Error("dial did not bind a local port")
	}
}

func TestTCPDialCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var port lportForTCPConn
	c, err := tcpDial(ctx, &port, netip.MustParseAddrPort("127.0.0.1:1"))
	if c != nil {
		c.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v; want context.Canceled", err)
	}
}

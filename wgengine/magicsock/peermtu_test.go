// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package magicsock

import (
	"syscall"
	"testing"

	"tailscale.com/envknob"
	"tailscale.com/net/sockopts"
)

func TestUDPSocketsDontFragment(t *testing.T) {
	if !hasUDPTransport {
		t.Skip("no UDP transport")
	}
	const sockets = 4
	c, _ := newTestConnAndRegistry(t, func(o *Options) { o.UDPSockets = sockets })
	// Enable only after NewConn.
	envknob.SetenvForTest(t, "TS_DEBUG_ENABLE_PMTUD", "true")
	if c.PeerMTUEnabled() {
		t.Fatal("peer MTU already enabled before UpdatePMTUD")
	}

	c.UpdatePMTUD()
	if !c.PeerMTUEnabled() {
		t.Fatal("peer MTU not enabled")
	}
	for i, pconn := range c.pconn4.group.conns {
		rc, err := sockopts.RawConn(pconn)
		if err != nil {
			t.Fatal(err)
		}
		var v int
		var optErr error
		if err := rc.Control(func(fd uintptr) {
			v, optErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER)
		}); err != nil {
			t.Fatal(err)
		}
		if optErr != nil {
			t.Fatalf("socket %d: %v", i, optErr)
		}
		if v != syscall.IP_PMTUDISC_DO {
			t.Errorf("socket %d: IP_MTU_DISCOVER = %d, want %d", i, v, syscall.IP_PMTUDISC_DO)
		}
	}
}

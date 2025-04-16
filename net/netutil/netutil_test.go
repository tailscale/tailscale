// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netutil

import (
	"io"
	"net"
	"runtime"
	"testing"

	"tailscale.com/net/netmon"
	"tailscale.com/util/eventbus"
)

type conn struct {
	net.Conn
}

func TestOneConnListener(t *testing.T) {
	c1 := new(conn)
	a1 := dummyAddr("a1")

	// Two Accepts
	ln := NewOneConnListener(c1, a1)
	if got := ln.Addr(); got != a1 {
		t.Errorf("Addr = %#v; want %#v", got, a1)
	}
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if c != c1 {
		t.Fatalf("didn't get c1; got %p", c)
	}
	c, err = ln.Accept()
	if err != io.EOF {
		t.Errorf("got %v; want EOF", err)
	}
	if c != nil {
		t.Errorf("unexpected non-nil Conn")
	}

	// Close before Accept
	ln = NewOneConnListener(c1, a1)
	ln.Close()
	_, err = ln.Accept()
	if err != io.EOF {
		t.Fatalf("got %v; want EOF", err)
	}

	// Implicit addr
	ln = NewOneConnListener(c1, nil)
	if ln.Addr() == nil {
		t.Errorf("nil Addr")
	}
}

func TestIPForwardingEnabledLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("skipping on %s", runtime.GOOS)
	}
	got, err := ipForwardingEnabledLinux(ipv4, "some-not-found-interface")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Errorf("got true; want false")
	}
}

func TestCheckReversePathFiltering(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("skipping on %s", runtime.GOOS)
	}
	bus := eventbus.New()
	defer bus.Close()

	netMon, err := netmon.New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer netMon.Close()

	warn, err := CheckReversePathFiltering(netMon.InterfaceState())
	t.Logf("err: %v", err)
	t.Logf("warnings: %v", warn)
}

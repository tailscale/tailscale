// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (darwin && !ios) || (linux && !android)

package magicsock

import (
	"context"
	"net"
	"syscall"
	"testing"
)

// A connected socket is dialled with the shared socket's don't-fragment setting, whichever way path MTU discovery has set it, so it sends exactly as the shared socket it stands in for would.
func TestConnectedCopiesDontFragment(t *testing.T) {
	c := newConn(t.Logf)
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	c.pconn4.mu.Lock()
	c.pconn4.pconn = pc
	c.pconn4.mu.Unlock()

	get := func(rc syscall.RawConn) int {
		t.Helper()
		var v int
		var gerr error
		if err := rc.Control(func(fd uintptr) { v, gerr = syscall.GetsockoptInt(int(fd), getIPProto("udp4"), getDontFragOpt("udp4")) }); err != nil || gerr != nil {
			t.Fatalf("getsockopt: %v, %v", err, gerr)
		}
		return v
	}
	seen := map[int]bool{}
	for _, enable := range []bool{true, false} {
		if err := c.setDontFragment("udp4", enable); err != nil {
			t.Fatalf("setDontFragment(%v): %v", enable, err)
		}
		lc := net.ListenConfig{Control: func(network, address string, rc syscall.RawConn) error { return c.copyDontFragment(network, rc) }}
		cc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		src, _ := pc.SyscallConn()
		dst, _ := cc.(*net.UDPConn).SyscallConn()
		want, got := get(src), get(dst)
		cc.Close()
		if got != want {
			t.Errorf("with don't-fragment %v the shared socket has %d and the connected one %d", enable, want, got)
		}
		seen[want] = true
	}
	if len(seen) != 2 {
		t.Fatalf("the shared socket's setting did not change between on and off (%v), so the test proves nothing", seen)
	}
}

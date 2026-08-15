// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package icmplistener

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

func TestListenPacket(t *testing.T) {
	ctx := context.Background()
	var lc ListenConfig
	pc, err := lc.ListenPacket(ctx, "ip:icmp", "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	rc, err := pc.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}

	assertSockOpt := func(name string, fd uintptr, opt, want int) {
		got, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, opt)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("unexpected sockopt %s: got %v, want %v", name, got, want)
		}
	}

	assertFcntl := func(name string, fd uintptr, cmd, arg, want int) {
		got, err := unix.FcntlInt(fd, cmd, arg)
		if err != nil {
			t.Fatal(err)
		}
		if cmd == syscall.F_GETFL {
			if arg&got != 0 {
				got = 1
			} else {
				got = 0
			}
		}
		if got != want {
			t.Fatalf("unexpected fcntl %s: got %v, want %v", name, got, want)
		}
	}

	rc.Control(func(fd uintptr) {
		wantTyp := syscall.SOCK_DGRAM
		if os.Geteuid() == 0 {
			wantTyp = syscall.SOCK_RAW
		}

		assertSockOpt("TYPE", fd, syscall.SO_TYPE, wantTyp)
		assertSockOpt("PROTOCOL", fd, syscall.SO_PROTOCOL, syscall.IPPROTO_ICMPV6)
		// TODO: check IPV6_V6ONLY.

		// Most of these options are set by the stdlib wrapper on the way to a
		// pollable, but they're worth checking as failure to set them is a
		// significant change on various axes, such as performance.
		assertSockOpt("REUSEADDR", fd, syscall.SO_REUSEADDR, 1)
		assertFcntl("NONBLOCK", fd, syscall.F_GETFL, syscall.O_NONBLOCK, 1)
		assertFcntl("CLOEXEC", fd, syscall.F_GETFD, syscall.O_CLOEXEC, 1)
	})
}

func TestPing(t *testing.T) {
	ctx := context.Background()
	var lc ListenConfig
	pc, err := lc.ListenPacket(ctx, "ip:icmp", "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}

	localhost := "127.0.0.1:1"
	dst, err := net.ResolveUDPAddr("udp", localhost)
	if err != nil {
		t.Fatal(err)
	}
	b, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0,
			Seq:  0,
			Data: []byte("hello"),
		},
	}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo(b, dst); err != nil {
		t.Fatal(err)
	}
	b = make([]byte, 1500)
	n, _, err := pc.ReadFrom(b)
	if err != nil {
		t.Fatal(err)
	}
	m, err := icmp.ParseMessage(1, b[:n])
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != ipv4.ICMPTypeEchoReply {
		t.Fatalf("got ICMP type %v, want %v", m.Type, ipv4.ICMPTypeEchoReply)
	}
	if string(m.Body.(*icmp.Echo).Data) != "hello" {
		t.Fatalf("got ICMP body %q, want %q", m.Body, "hello")
	}
}

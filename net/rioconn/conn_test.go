// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"net/netip"
	"syscall"
	"testing"
)

func TestNewConn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		sotype      int32
		proto       int32
		dualStack   bool
		laddr       netip.AddrPort
		wantErr     bool
		wantNetwork string
		wantFamily  int32
		wantPort    uint16 // 0 means any port
		wantAddr    netip.Addr
	}{
		{
			name:        "IPv4/UDP/AnyAddr/EphemeralPort",
			sotype:      syscall.SOCK_DGRAM,
			proto:       syscall.IPPROTO_UDP,
			laddr:       netip.MustParseAddrPort("0.0.0.0:0"),
			wantAddr:    netip.MustParseAddr("0.0.0.0"),
			wantFamily:  syscall.AF_INET,
			wantNetwork: "udp4",
		},
		{
			name:        "IPv6/UDP/AnyAddr/EphemeralPort",
			sotype:      syscall.SOCK_DGRAM,
			proto:       syscall.IPPROTO_UDP,
			laddr:       netip.MustParseAddrPort("[::]:0"),
			wantAddr:    netip.MustParseAddr("::"),
			wantFamily:  syscall.AF_INET6,
			wantNetwork: "udp6",
		},
		{
			name:        "IPv4/UDP/LoopbackAddr/EphemeralPort",
			sotype:      syscall.SOCK_DGRAM,
			proto:       syscall.IPPROTO_UDP,
			laddr:       netip.MustParseAddrPort("127.0.0.1:0"),
			wantAddr:    netip.MustParseAddr("127.0.0.1"),
			wantFamily:  syscall.AF_INET,
			wantNetwork: "udp4",
		},
		{
			name:        "IPv6/UDP/LoopbackAddr/EphemeralPort",
			sotype:      syscall.SOCK_DGRAM,
			proto:       syscall.IPPROTO_UDP,
			laddr:       netip.MustParseAddrPort("[::1]:0"),
			wantAddr:    netip.MustParseAddr("::1"),
			wantFamily:  syscall.AF_INET6,
			wantNetwork: "udp6",
		},
		{
			name:        "IPv6/UDP/AnyAddr/EphemeralPort/DualStack",
			sotype:      syscall.SOCK_DGRAM,
			proto:       syscall.IPPROTO_UDP,
			dualStack:   true,
			laddr:       netip.MustParseAddrPort("[::]:0"),
			wantAddr:    netip.MustParseAddr("::"),
			wantFamily:  syscall.AF_INET6,
			wantNetwork: "udp",
		},
		{
			name:        "IPv4/TCP/AnyAddr/EphemeralPort",
			sotype:      syscall.SOCK_STREAM,
			proto:       syscall.IPPROTO_TCP,
			laddr:       netip.MustParseAddrPort("0.0.0.0:0"),
			wantAddr:    netip.MustParseAddr("0.0.0.0"),
			wantFamily:  syscall.AF_INET,
			wantNetwork: "tcp4",
		},
		{
			name:        "IPv6/TCP/AnyAddr/EphemeralPort",
			sotype:      syscall.SOCK_STREAM,
			proto:       syscall.IPPROTO_TCP,
			laddr:       netip.MustParseAddrPort("[::]:0"),
			wantAddr:    netip.MustParseAddr("::"),
			wantFamily:  syscall.AF_INET6,
			wantNetwork: "tcp6",
		},
		{
			name:        "IPv6/TCP/AnyAddr/EphemeralPort/DualStack",
			sotype:      syscall.SOCK_STREAM,
			proto:       syscall.IPPROTO_TCP,
			dualStack:   true,
			laddr:       netip.MustParseAddrPort("[::]:0"),
			wantAddr:    netip.MustParseAddr("::"),
			wantFamily:  syscall.AF_INET6,
			wantNetwork: "tcp",
		},
		{
			name:    "InvalidSOType",
			sotype:  12345,
			proto:   syscall.IPPROTO_UDP,
			laddr:   netip.MustParseAddrPort("0.0.0.0:0"),
			wantErr: true,
		},
		{
			name:    "InvalidProtocol",
			sotype:  syscall.SOCK_DGRAM,
			proto:   12345,
			laddr:   netip.MustParseAddrPort("0.0.0.0:0"),
			wantErr: true,
		},
		{
			name:    "InvalidAddress",
			sotype:  syscall.SOCK_DGRAM,
			proto:   syscall.IPPROTO_UDP,
			laddr:   netip.AddrPort{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, err := newConn(tt.sotype, tt.proto, tt.dualStack, tt.laddr, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("newConn: got error %v, want: %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			t.Cleanup(func() {
				if err := c.Close(); err != nil {
					t.Fatalf("Close failed: %v", err)
				}
			})

			if got := c.Network(); got != tt.wantNetwork {
				t.Errorf("newConn: got network %q, want %q", got, tt.wantNetwork)
			}

			if got := c.IsDualStack(); got != tt.dualStack {
				t.Errorf("newConn: got dualStack %v, want %v", got, tt.dualStack)
			}

			if got := c.Family(); got != tt.wantFamily {
				t.Errorf("newConn: got family %d, want %d", got, tt.wantFamily)
			}

			gotAddrPort := c.LocalAddrPort()
			if !gotAddrPort.IsValid() {
				t.Fatalf("newConn: got invalid local address %v", gotAddrPort)
			}

			if gotAddrPort.Addr() != tt.wantAddr {
				t.Errorf("newConn: got address %v, want %v", gotAddrPort.Addr(), tt.wantAddr)
			}

			if tt.wantPort != 0 && gotAddrPort.Port() != tt.wantPort {
				t.Errorf("newConn: got port %d, want %d", gotAddrPort.Port(), tt.wantPort)
			} else if gotAddrPort.Port() == 0 {
				t.Errorf("newConn: got port 0, want non-zero")
			}

			if c.LocalAddr().String() != gotAddrPort.String() {
				t.Errorf("newConn: LocalAddr %q, LocalAddrPort %q", c.LocalAddr(), gotAddrPort)
			}

		})
	}
}

func TestConnAcquireReleaseClose(t *testing.T) {
	t.Parallel()

	c, err := newConn(syscall.SOCK_DGRAM, syscall.IPPROTO_UDP, false, netip.MustParseAddrPort("0.0.0.0:0"), nil)
	if err != nil {
		t.Fatalf("newConn failed: %v", err)
	}
	if c.IsClosed() {
		t.Fatal("newConn: got closed connection")
	}
	if err := c.acquire(); err != nil {
		t.Errorf("acquire failed: %v", err)
	}
	go c.release() // race with close
	if err := c.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if !c.IsClosed() {
		t.Fatal("Close did not mark connection as closed")
	}
	if err := c.acquire(); err == nil {
		t.Fatal("acquire succeeded on closed connection")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close failed on already closed connection: %v", err)
	}
}

func TestSyscallConn(t *testing.T) {
	t.Parallel()

	c, err := newConn(syscall.SOCK_DGRAM, syscall.IPPROTO_UDP, false,
		netip.MustParseAddrPort("0.0.0.0:0"), nil)
	if err != nil {
		t.Fatalf("newConn failed: %v", err)
	}
	defer c.Close()

	syscallConn, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn failed: %v", err)
	}

	err = syscallConn.Control(func(fd uintptr) {
		if fd != uintptr(c.socket) {
			t.Fatalf("Control: got fd %v, want %v", fd, c.socket)
		}
	})
	if err != nil {
		t.Fatalf("Control failed: %v", err)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	err = syscallConn.Control(func(fd uintptr) {
		t.Fatalf("Control succeeded on closed connection with fd %v", fd)
	})
	if err == nil {
		t.Fatal("Control succeeded on closed connection")
	}
}

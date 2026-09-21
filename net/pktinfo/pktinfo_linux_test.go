// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package pktinfo

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/must"
)

// TestReplySourceAddr verifies that an echo server using this package
// replies from the address the request was sent to, not from whichever
// address the kernel would otherwise pick for the reply's destination.
// It sends from 127.0.0.1 to the server at 127.0.0.2 (all of 127/8 is
// local on Linux); without pktinfo the kernel replies from 127.0.0.1.
func TestReplySourceAddr(t *testing.T) {
	tests := []struct {
		name    string
		network string // "udp" for a dual-stack socket, "udp4" for AF_INET
		pktInfo bool   // whether to use pktinfo; false is the negative control
	}{
		{"dualstack", "udp", true},
		{"dualstack-nopktinfo", "udp", false},
		{"v4", "udp4", true},
		{"v4-nopktinfo", "udp4", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.network == "udp" {
				// The dual-stack cases need an AF_INET6 socket,
				// which net.ListenUDP("udp") quietly won't
				// create on a host with IPv6 disabled.
				if c, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
					if !cibuild.On() {
						t.Skipf("IPv6 not supported: %v", err)
					}
					t.Fatalf("IPv6 not supported: %v", err)
				} else {
					c.Close()
				}
			}
			srv := must.Get(net.ListenUDP(tt.network, nil))
			defer srv.Close()
			if tt.pktInfo {
				if err := Enable(srv); err != nil {
					t.Fatalf("Enable: %v", err)
				}
			}
			go func() {
				var buf, oob [1500]byte
				n, oobn, _, from, err := srv.ReadMsgUDPAddrPort(buf[:], oob[:])
				if err != nil {
					return
				}
				srv.WriteMsgUDPAddrPort(buf[:n], AppendSrc(nil, Dst(oob[:oobn])), from)
			}()
			port := uint16(srv.LocalAddr().(*net.UDPAddr).Port)
			serverAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), port)

			c := must.Get(net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}))
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			must.Get(c.WriteToUDPAddrPort([]byte("hello"), serverAddr))

			var buf [1500]byte
			n, from, err := c.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				t.Fatalf("reading reply: %v", err)
			}
			if string(buf[:n]) != "hello" {
				t.Errorf("reply = %q; want %q", buf[:n], "hello")
			}
			wantFrom := serverAddr
			if !tt.pktInfo {
				wantFrom = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
			}
			if from != wantFrom {
				t.Errorf("reply came from %v; want %v", from, wantFrom)
			}
		})
	}
}

// TestAppendSrcMatchesUnix checks the hand-built control messages against
// the ones x/sys/unix builds.
func TestAppendSrcMatchesUnix(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.1")
	v6 := netip.MustParseAddr("2001:db8::1")

	want4 := unix.PktInfo4(&unix.Inet4Pktinfo{Spec_dst: v4.As4()})
	if got := AppendSrc(nil, v4); string(got) != string(want4) {
		t.Errorf("v4: got % x, want % x", got, want4)
	}
	want6 := unix.PktInfo6(&unix.Inet6Pktinfo{Addr: v6.As16()})
	if got := AppendSrc(nil, v6); string(got) != string(want6) {
		t.Errorf("v6: got % x, want % x", got, want6)
	}
	if got := AppendSrc([]byte("prefix"), v4); string(got) != "prefix"+string(want4) {
		t.Errorf("append: got % x", got)
	}
	for _, a := range []netip.Addr{{}, netip.IPv4Unspecified(), netip.IPv6Unspecified(), netip.MustParseAddr("224.0.0.1"), netip.MustParseAddr("ff02::1")} {
		if got := AppendSrc(nil, a); got != nil {
			t.Errorf("AppendSrc(%v) = % x; want nil", a, got)
		}
	}
	if got := Dst(want4); got != v4 {
		t.Errorf("Dst(v4 pktinfo) = %v; want %v", got, v4)
	}
	if got := Dst(want6); got != v6 {
		t.Errorf("Dst(v6 pktinfo) = %v; want %v", got, v6)
	}
	mapped := unix.PktInfo6(&unix.Inet6Pktinfo{Addr: v4.As16()})
	if got := Dst(mapped); got != v4 {
		t.Errorf("Dst(mapped v4 pktinfo) = %v; want %v", got, v4)
	}
}

// TestBroadcastDst verifies that an IPv4 broadcast datagram received on a
// dual-stack socket reports a unicast reply address, not the broadcast
// address, and that the reply then actually gets out. It needs a
// broadcast-capable interface and skips without one.
func TestBroadcastDst(t *testing.T) {
	var local, bcast netip.Addr
	ifs := must.Get(net.Interfaces())
	for _, ifi := range ifs {
		const want = net.FlagUp | net.FlagBroadcast
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&want != want {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			pfx := must.Get(netip.ParsePrefix(ipn.String())).Masked()
			if pfx.Bits() > 30 {
				continue // no directed broadcast address
			}
			local, _ = netip.AddrFromSlice(ipn.IP.To4())
			b := pfx.Addr().As4()
			for i := range b {
				b[i] |= ^ipn.Mask[i]
			}
			bcast = netip.AddrFrom4(b)
			break
		}
		if bcast.IsValid() {
			break
		}
	}
	if !bcast.IsValid() {
		t.Skip("no broadcast-capable IPv4 interface")
	}
	t.Logf("using local %v, broadcast %v", local, bcast)

	srv := must.Get(net.ListenUDP("udp", nil))
	defer srv.Close()
	must.Do(Enable(srv))
	port := uint16(srv.LocalAddr().(*net.UDPAddr).Port)
	gotDst := make(chan netip.Addr, 1)
	go func() {
		var buf, oob [1500]byte
		n, oobn, _, from, err := srv.ReadMsgUDPAddrPort(buf[:], oob[:])
		if err != nil {
			return
		}
		dst := Dst(oob[:oobn])
		gotDst <- dst
		srv.WriteMsgUDPAddrPort(buf[:n], AppendSrc(nil, dst), from)
	}()

	c := must.Get(net.ListenUDP("udp4", &net.UDPAddr{IP: local.AsSlice()}))
	defer c.Close()
	rc := must.Get(c.SyscallConn())
	rc.Control(func(fd uintptr) {
		must.Do(unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1))
	})
	c.SetDeadline(time.Now().Add(5 * time.Second))
	must.Get(c.WriteToUDPAddrPort([]byte("hello"), netip.AddrPortFrom(bcast, port)))

	var buf [1500]byte
	_, from, err := c.ReadFromUDPAddrPort(buf[:])
	if err != nil {
		t.Fatalf("reading reply: %v", err)
	}
	if dst := <-gotDst; dst != local {
		t.Errorf("Dst = %v; want %v", dst, local)
	}
	if from.Addr() != local {
		t.Errorf("reply came from %v; want %v", from.Addr(), local)
	}
}

// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstun

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/tailscale/wireguard-go/tun/tuntest"
	"inet.af/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

func udp(src, dst packet.IP4, sport, dport uint16) []byte {
	header := &packet.UDP4Header{
		IP4Header: packet.IP4Header{
			SrcIP: src,
			DstIP: dst,
			IPID:  0,
		},
		SrcPort: sport,
		DstPort: dport,
	}
	return packet.Generate(header, []byte("udp_payload"))
}

func nets(nets ...string) (ret []netaddr.IPPrefix) {
	for _, s := range nets {
		if i := strings.IndexByte(s, '/'); i == -1 {
			ip, err := netaddr.ParseIP(s)
			if err != nil {
				panic(err)
			}
			bits := uint8(32)
			if ip.Is6() {
				bits = 128
			}
			ret = append(ret, netaddr.IPPrefix{IP: ip, Bits: bits})
		} else {
			pfx, err := netaddr.ParseIPPrefix(s)
			if err != nil {
				panic(err)
			}
			ret = append(ret, pfx)
		}
	}
	return ret
}

func ports(s string) filter.PortRange {
	if s == "*" {
		return filter.PortRange{First: 0, Last: 65535}
	}

	var fs, ls string
	i := strings.IndexByte(s, '-')
	if i == -1 {
		fs = s
		ls = fs
	} else {
		fs = s[:i]
		ls = s[i+1:]
	}
	first, err := strconv.ParseInt(fs, 10, 16)
	if err != nil {
		panic(fmt.Sprintf("invalid NetPortRange %q", s))
	}
	last, err := strconv.ParseInt(ls, 10, 16)
	if err != nil {
		panic(fmt.Sprintf("invalid NetPortRange %q", s))
	}
	return filter.PortRange{First: uint16(first), Last: uint16(last)}
}

func netports(netPorts ...string) (ret []filter.NetPortRange) {
	for _, s := range netPorts {
		i := strings.LastIndexByte(s, ':')
		if i == -1 {
			panic(fmt.Sprintf("invalid NetPortRange %q", s))
		}

		npr := filter.NetPortRange{
			Net:   nets(s[:i])[0],
			Ports: ports(s[i+1:]),
		}
		ret = append(ret, npr)
	}
	return ret
}

func setfilter(logf logger.Logf, tun *TUN) {
	matches := []filter.Match{
		{Srcs: nets("5.6.7.8"), Dsts: netports("1.2.3.4:89-90")},
		{Srcs: nets("1.2.3.4"), Dsts: netports("5.6.7.8:98")},
	}
	localNets := nets("1.2.0.0/16")
	tun.SetFilter(filter.New(matches, localNets, nil, logf))
}

func newChannelTUN(logf logger.Logf, secure bool) (*tuntest.ChannelTUN, *TUN) {
	chtun := tuntest.NewChannelTUN()
	tun := WrapTUN(logf, chtun.TUN())
	if secure {
		setfilter(logf, tun)
	} else {
		tun.disableFilter = true
	}
	return chtun, tun
}

func newFakeTUN(logf logger.Logf, secure bool) (*fakeTUN, *TUN) {
	ftun := NewFakeTUN()
	tun := WrapTUN(logf, ftun)
	if secure {
		setfilter(logf, tun)
	} else {
		tun.disableFilter = true
	}
	return ftun.(*fakeTUN), tun
}

func TestReadAndInject(t *testing.T) {
	chtun, tun := newChannelTUN(t.Logf, false)
	defer tun.Close()

	const size = 2 // all payloads have this size
	written := []string{"w0", "w1"}
	injected := []string{"i0", "i1"}

	go func() {
		for _, packet := range written {
			payload := []byte(packet)
			chtun.Outbound <- payload
		}
	}()

	for _, packet := range injected {
		go func(packet string) {
			payload := []byte(packet)
			err := tun.InjectOutbound(payload)
			if err != nil {
				t.Errorf("%s: error: %v", packet, err)
			}
		}(packet)
	}

	var buf [MaxPacketSize]byte
	var seen = make(map[string]bool)
	// We expect the same packets back, in no particular order.
	for i := 0; i < len(written)+len(injected); i++ {
		n, err := tun.Read(buf[:], 0)
		if err != nil {
			t.Errorf("read %d: error: %v", i, err)
		}
		if n != size {
			t.Errorf("read %d: got size %d; want %d", i, n, size)
		}
		got := string(buf[:n])
		t.Logf("read %d: got %s", i, got)
		seen[got] = true
	}

	for _, packet := range written {
		if !seen[packet] {
			t.Errorf("%s not received", packet)
		}
	}
	for _, packet := range injected {
		if !seen[packet] {
			t.Errorf("%s not received", packet)
		}
	}
}

func TestWriteAndInject(t *testing.T) {
	chtun, tun := newChannelTUN(t.Logf, false)
	defer tun.Close()

	const size = 2 // all payloads have this size
	written := []string{"w0", "w1"}
	injected := []string{"i0", "i1"}

	go func() {
		for _, packet := range written {
			payload := []byte(packet)
			n, err := tun.Write(payload, 0)
			if err != nil {
				t.Errorf("%s: error: %v", packet, err)
			}
			if n != size {
				t.Errorf("%s: got size %d; want %d", packet, n, size)
			}
		}
	}()

	for _, packet := range injected {
		go func(packet string) {
			payload := []byte(packet)
			err := tun.InjectInboundCopy(payload)
			if err != nil {
				t.Errorf("%s: error: %v", packet, err)
			}
		}(packet)
	}

	seen := make(map[string]bool)
	// We expect the same packets back, in no particular order.
	for i := 0; i < len(written)+len(injected); i++ {
		packet := <-chtun.Inbound
		got := string(packet)
		t.Logf("read %d: got %s", i, got)
		seen[got] = true
	}

	for _, packet := range written {
		if !seen[packet] {
			t.Errorf("%s not received", packet)
		}
	}
	for _, packet := range injected {
		if !seen[packet] {
			t.Errorf("%s not received", packet)
		}
	}
}

func TestFilter(t *testing.T) {
	chtun, tun := newChannelTUN(t.Logf, true)
	defer tun.Close()

	type direction int

	const (
		in direction = iota
		out
	)

	tests := []struct {
		name string
		dir  direction
		drop bool
		data []byte
	}{
		{"junk_in", in, true, []byte("\x45not a valid IPv4 packet")},
		{"junk_out", out, true, []byte("\x45not a valid IPv4 packet")},
		{"bad_port_in", in, true, udp(0x05060708, 0x01020304, 22, 22)},
		{"bad_port_out", out, false, udp(0x01020304, 0x05060708, 22, 22)},
		{"bad_ip_in", in, true, udp(0x08010101, 0x01020304, 89, 89)},
		{"bad_ip_out", out, false, udp(0x01020304, 0x08010101, 98, 98)},
		{"good_packet_in", in, false, udp(0x05060708, 0x01020304, 89, 89)},
		{"good_packet_out", out, false, udp(0x01020304, 0x05060708, 98, 98)},
	}

	// A reader on the other end of the TUN.
	go func() {
		var recvbuf []byte
		for {
			select {
			case <-tun.closed:
				return
			case recvbuf = <-chtun.Inbound:
				// continue
			}
			for _, tt := range tests {
				if tt.drop && bytes.Equal(recvbuf, tt.data) {
					t.Errorf("did not drop %s", tt.name)
				}
			}
		}
	}()

	var buf [MaxPacketSize]byte
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var n int
			var err error
			var filtered bool

			if tt.dir == in {
				_, err = tun.Write(tt.data, 0)
				if err == ErrFiltered {
					filtered = true
					err = nil
				}
			} else {
				chtun.Outbound <- tt.data
				n, err = tun.Read(buf[:], 0)
				// In the read direction, errors are fatal, so we return n = 0 instead.
				filtered = (n == 0)
			}

			if err != nil {
				t.Errorf("got err %v; want nil", err)
			}

			if filtered {
				if !tt.drop {
					t.Errorf("got drop; want accept")
				}
			} else {
				if tt.drop {
					t.Errorf("got accept; want drop")
				}
			}
		})
	}
}

func TestAllocs(t *testing.T) {
	ftun, tun := newFakeTUN(t.Logf, false)
	defer tun.Close()

	buf := []byte{0x00}
	allocs := testing.AllocsPerRun(100, func() {
		_, err := ftun.Write(buf, 0)
		if err != nil {
			t.Errorf("write: error: %v", err)
			return
		}
	})

	if allocs > 0 {
		t.Errorf("read allocs = %v; want 0", allocs)
	}
}

func BenchmarkWrite(b *testing.B) {
	ftun, tun := newFakeTUN(b.Logf, true)
	defer tun.Close()

	packet := udp(0x05060708, 0x01020304, 89, 89)
	for i := 0; i < b.N; i++ {
		_, err := ftun.Write(packet, 0)
		if err != nil {
			b.Errorf("err = %v; want nil", err)
		}
	}
}

func TestAtomic64Alignment(t *testing.T) {
	off := unsafe.Offsetof(TUN{}.lastActivityAtomic)
	if off%8 != 0 {
		t.Errorf("offset %v not 8-byte aligned", off)
	}

	c := new(TUN)
	atomic.StoreInt64(&c.lastActivityAtomic, 123)
}

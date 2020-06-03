// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package tstun

import (
	"bytes"
	"testing"

	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/packet"
)

func newTUN(logf logger.Logf) (*tuntest.ChannelTUN, *TUN) {
	chtun := tuntest.NewChannelTUN()
	tun := WrapTUN(logf, chtun.TUN())
	return chtun, tun
}

func newInsecureTUN(logf logger.Logf) (*tuntest.ChannelTUN, *TUN) {
	chtun, tun := newTUN(logf)
	tun.insecure = true
	return chtun, tun
}

func TestReadAndInject(t *testing.T) {
	chtun, tun := newInsecureTUN(t.Logf)
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
	chtun, tun := newInsecureTUN(t.Logf)
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
			err := tun.InjectInbound(payload)
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

func TestAllocs(t *testing.T) {
	chtun, tun := newInsecureTUN(t.Logf)
	defer tun.Close()
	buf := make([]byte, 1)

	go func() {
		chtun.Outbound <- []byte{0x00}
		for {
			select {
			case buf := <-chtun.Inbound:
				chtun.Outbound <- buf
			case <-tun.closed:
				return
			}
		}
	}()

	allocs := testing.AllocsPerRun(100, func() {
		_, err := tun.Read(buf, 0)
		if err != nil {
			t.Errorf("read: error: %v", err)
			return
		}

		_, err = tun.Write(buf, 0)
		if err != nil {
			t.Errorf("write: error: %v", err)
			return
		}
	})

	// One allocation is in chTun.Write
	if allocs > 1 {
		t.Errorf("read allocs = %v; want 1", allocs)
	}
}

func udp(src, dst packet.IP, sport, dport uint16) []byte {
	header := packet.UDPHeader{
		IPHeader: packet.IPHeader{
			SrcIP: src,
			DstIP: dst,
			IPID:  0,
		},
		SrcPort: sport,
		DstPort: dport,
	}
	return header.NewPacketWithPayload([]byte("udp_payload"))
}

func nets(ips []packet.IP) []filter.Net {
	out := make([]filter.Net, 0, len(ips))
	for _, ip := range ips {
		out = append(out, filter.Net{ip, filter.Netmask(32)})
	}
	return out
}

func ippr(ip packet.IP, start, end uint16) []filter.NetPortRange {
	return []filter.NetPortRange{
		filter.NetPortRange{filter.Net{ip, filter.Netmask(32)}, filter.PortRange{start, end}},
	}
}

func netpr(ip packet.IP, bits int, start, end uint16) []filter.NetPortRange {
	return []filter.NetPortRange{
		filter.NetPortRange{filter.Net{ip, filter.Netmask(bits)}, filter.PortRange{start, end}},
	}
}

func TestFilter(t *testing.T) {
	chtun, tun := newTUN(t.Logf)
	defer tun.Close()

	matches := filter.Matches{
		{Srcs: nets([]packet.IP{0x05060708}), Dsts: ippr(0x01020304, 89, 90)},
		{Srcs: nets([]packet.IP{0x01020304}), Dsts: ippr(0x05060708, 98, 98)},
	}
	localNets := []filter.Net{
		{packet.IP(0x01020304), filter.Netmask(16)},
	}
	tun.SetFilter(filter.New(matches, localNets, nil, t.Logf))

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
			case recvbuf = <-chtun.Inbound:
				// continue
			case <-tun.closed:
				return
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

func BenchmarkWrite(b *testing.B) {
	chtun, tun := newInsecureTUN(b.Logf)
	defer tun.Close()

	go func() {
		for {
			select {
			case <-chtun.Inbound:
				// continue
			case <-tun.closed:
				return
			}
		}
	}()

	packet := udp(0x12345678, 0x87654321, 123, 456)
	for i := 0; i < b.N; i++ {
		_, err := tun.Write(packet, 0)
		if err != nil {
			b.Errorf("err = %v; want nil", err)
		}
	}
}

func BenchmarkRead(b *testing.B) {
	chtun, tun := newInsecureTUN(b.Logf)
	defer tun.Close()

	packet := udp(0x12345678, 0x87654321, 123, 456)

	go func() {
		for {
			select {
			case chtun.Outbound <- packet:
				// continue
			case <-tun.closed:
				return
			}
		}
	}()

	var buf [128]byte
	for i := 0; i < b.N; i++ {
		_, err := tun.Read(buf[:], 0)
		if err != nil {
			b.Errorf("err = %v; want nil", err)
		}
	}
}

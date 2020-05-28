// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"

	"tailscale.com/types/logger"
	"tailscale.com/wgengine/packet"
)

// Type aliases only in test code: (but ideally nowhere)
type QDecode = packet.QDecode
type IP = packet.IP

var Junk = packet.Junk
var ICMP = packet.ICMP
var TCP = packet.TCP
var UDP = packet.UDP
var Fragment = packet.Fragment

func nets(ips []IP) []Net {
	out := make([]Net, 0, len(ips))
	for _, ip := range ips {
		out = append(out, Net{ip, Netmask(32)})
	}
	return out
}

func ippr(ip IP, start, end uint16) []NetPortRange {
	return []NetPortRange{
		NetPortRange{Net{ip, Netmask(32)}, PortRange{start, end}},
	}
}

func netpr(ip IP, bits int, start, end uint16) []NetPortRange {
	return []NetPortRange{
		NetPortRange{Net{ip, Netmask(bits)}, PortRange{start, end}},
	}
}

var matches = Matches{
	{Srcs: nets([]IP{0x08010101, 0x08020202}), Dsts: []NetPortRange{
		NetPortRange{Net{0x01020304, Netmask(32)}, PortRange{22, 22}},
		NetPortRange{Net{0x05060708, Netmask(32)}, PortRange{23, 24}},
	}},
	{Srcs: nets([]IP{0x08010101, 0x08020202}), Dsts: ippr(0x05060708, 27, 28)},
	{Srcs: nets([]IP{0x02020202}), Dsts: ippr(0x08010101, 22, 22)},
	{Srcs: []Net{NetAny}, Dsts: ippr(0x647a6232, 0, 65535)},
	{Srcs: []Net{NetAny}, Dsts: netpr(0, 0, 443, 443)},
	{Srcs: nets([]IP{0x99010101, 0x99010102, 0x99030303}), Dsts: ippr(0x01020304, 999, 999)},
}

func newFilter(logf logger.Logf) *Filter {
	// Expects traffic to 100.122.98.50, 1.2.3.4, 5.6.7.8,
	// 102.102.102.102, 119.119.119.119, 8.1.0.0/16
	localNets := nets([]IP{0x647a6232, 0x01020304, 0x05060708, 0x66666666, 0x77777777})
	localNets = append(localNets, Net{IP(0x08010000), Netmask(16)})

	return New(matches, localNets, nil, logf)
}

func TestMarshal(t *testing.T) {
	for _, ent := range []Matches{Matches{matches[0]}, matches} {
		b, err := json.Marshal(ent)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		mm2 := Matches{}
		if err := json.Unmarshal(b, &mm2); err != nil {
			t.Fatalf("unmarshal: %v (%v)", err, string(b))
		}
	}
}

func TestFilter(t *testing.T) {
	acl := newFilter(t.Logf)
	// check packet filtering based on the table

	type InOut struct {
		want Response
		p    QDecode
	}
	tests := []InOut{
		// Basic
		{Accept, qdecode(TCP, 0x08010101, 0x01020304, 999, 22)},
		{Accept, qdecode(UDP, 0x08010101, 0x01020304, 999, 22)},
		{Accept, qdecode(ICMP, 0x08010101, 0x01020304, 0, 0)},
		{Drop, qdecode(TCP, 0x08010101, 0x01020304, 0, 0)},
		{Accept, qdecode(TCP, 0x08010101, 0x01020304, 0, 22)},
		{Drop, qdecode(TCP, 0x08010101, 0x01020304, 0, 21)},
		{Accept, qdecode(TCP, 0x11223344, 0x08012233, 0, 443)},
		{Drop, qdecode(TCP, 0x11223344, 0x08012233, 0, 444)},
		{Accept, qdecode(TCP, 0x11223344, 0x647a6232, 0, 999)},
		{Accept, qdecode(TCP, 0x11223344, 0x647a6232, 0, 0)},

		// localNets prefilter - accepted by policy filter, but
		// unexpected dst IP.
		{Drop, qdecode(TCP, 0x08010101, 0x10203040, 0, 443)},

		// Stateful UDP. Note each packet is run through the input
		// filter, then the output filter (which sets conntrack
		// state).
		// Initially empty cache
		{Drop, qdecode(UDP, 0x77777777, 0x66666666, 4242, 4343)},
		// Return packet from previous attempt is allowed
		{Accept, qdecode(UDP, 0x66666666, 0x77777777, 4343, 4242)},
		// Because of the return above, initial attempt is allowed now
		{Accept, qdecode(UDP, 0x77777777, 0x66666666, 4242, 4343)},
	}
	for i, test := range tests {
		if got, _ := acl.runIn(&test.p); test.want != got {
			t.Errorf("#%d got=%v want=%v packet:%v\n", i, got, test.want, test.p)
		}
		// Update UDP state
		_, _ = acl.runOut(&test.p)
	}
}

func TestNoAllocs(t *testing.T) {
	acl := newFilter(t.Logf)

	tcpPacket := tcpudp(TCP, 0x08010101, 0x01020304, 999, 22)
	udpPacket := tcpudp(UDP, 0x08010101, 0x01020304, 999, 22)

	tests := []struct {
		name   string
		in     bool
		want   float64
		packet []byte
	}{
		{"tcp_in", true, 0.0, tcpPacket},
		{"tcp_out", false, 0.0, tcpPacket},
		{"udp_in", true, 0.0, udpPacket},
		// One alloc is inevitable (an lru cache update)
		{"udp_out", false, 1.0, udpPacket},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := testing.AllocsPerRun(1000, func() {
				var q QDecode
				if test.in {
					acl.RunIn(test.packet, &q, 0)
				} else {
					acl.RunOut(test.packet, &q, 0)
				}
			})

			// It is OK to allocate once per 1000 runs or so (rate-limited logging).
			// We also bound got in both directions here to ensure we understand
			// our allocation behavior: if it improves, we should change the excepted values.
			if got-test.want > 0.001 || test.want-got > 0.001 {
				t.Errorf("got %.3f allocs per run; want %.3f", got, test.want)
			}
		})
	}
}

func BenchmarkFilter(b *testing.B) {
	acl := newFilter(b.Logf)

	benches := []struct {
		name   string
		packet []byte
	}{
		{"tcp", tcpudp(TCP, 0x08010101, 0x01020304, 999, 22)},
		{"udp", tcpudp(UDP, 0x08010101, 0x01020304, 999, 22)},
	}

	for _, bench := range benches {
		b.Run(bench.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				var q QDecode
				acl.RunIn(bench.packet, &q, 0)
			}
		})
	}
}

func TestPreFilter(t *testing.T) {
	packets := []struct {
		desc string
		want Response
		b    []byte
	}{
		{"empty", Accept, []byte{}},
		{"short", Drop, []byte("short")},
		{"junk", Drop, rawpacket(Junk, 10)},
		{"fragment", Accept, rawpacket(Fragment, 40)},
		{"tcp", noVerdict, rawpacket(TCP, 200)},
		{"udp", noVerdict, rawpacket(UDP, 200)},
		{"icmp", noVerdict, rawpacket(ICMP, 200)},
	}
	f := NewAllowNone(t.Logf)
	for _, testPacket := range packets {
		got := f.pre([]byte(testPacket.b), &QDecode{}, LogDrops|LogAccepts)
		if got != testPacket.want {
			t.Errorf("%q got=%v want=%v packet:\n%s", testPacket.desc, got, testPacket.want, packet.Hexdump(testPacket.b))
		}
	}
}

func qdecode(proto packet.IPProto, src, dst packet.IP, sport, dport uint16) QDecode {
	return QDecode{
		IPProto:  proto,
		SrcIP:    src,
		DstIP:    dst,
		SrcPort:  sport,
		DstPort:  dport,
		TCPFlags: packet.TCPSyn,
	}
}

func rawpacket(proto packet.IPProto, len uint16) []byte {
	bl := len
	if len < 24 {
		bl = 24
	}
	bin := binary.BigEndian
	hdr := make([]byte, bl)
	hdr[0] = 0x45
	bin.PutUint16(hdr[2:4], len)
	hdr[8] = 64
	ip := net.IPv4(8, 8, 8, 8).To4()
	copy(hdr[12:16], ip)
	copy(hdr[16:20], ip)
	// ports
	bin.PutUint16(hdr[20:22], 53)
	bin.PutUint16(hdr[22:24], 53)

	switch proto {
	case ICMP:
		hdr[9] = 1
	case TCP:
		hdr[9] = 6
	case UDP:
		hdr[9] = 17
	case Fragment:
		hdr[9] = 6
		// flags + fragOff
		bin.PutUint16(hdr[6:8], (1<<13)|1234)
	case Junk:
	default:
		panic("unknown protocol")
	}

	// Truncate the header if requested
	hdr = hdr[:len]

	return hdr
}

func tcpudp(proto packet.IPProto, src, dst packet.IP, sport, dport uint16) []byte {
	len := 40
	bin := binary.BigEndian
	hdr := make([]byte, 40)

	hdr[0] = 0x45
	bin.PutUint16(hdr[2:4], uint16(len))
	hdr[8] = 64
	if proto == TCP {
		hdr[9] = 6
	} else {
		hdr[9] = 17
	}
	bin.PutUint32(hdr[12:16], uint32(src))
	bin.PutUint32(hdr[16:20], uint32(dst))
	// ports
	bin.PutUint16(hdr[20:22], sport)
	bin.PutUint16(hdr[22:24], dport)
	if proto == TCP {
		hdr[33] = packet.TCPSyn
	}

	return hdr
}

// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestIPString(t *testing.T) {
	const str = "1.2.3.4"
	ip := NewIP(net.ParseIP(str))

	var got string
	allocs := testing.AllocsPerRun(1000, func() {
		got = ip.String()
	})

	if got != str {
		t.Errorf("got %q; want %q", got, str)
	}
	if allocs != 1 {
		t.Errorf("allocs = %v; want 1", allocs)
	}
}

func TestQDecodeString(t *testing.T) {
	q := QDecode{
		IPProto: TCP,
		SrcIP:   NewIP(net.ParseIP("1.2.3.4")),
		SrcPort: 123,
		DstIP:   NewIP(net.ParseIP("5.6.7.8")),
		DstPort: 567,
	}
	got := q.String()
	want := "TCP{1.2.3.4:123 > 5.6.7.8:567}"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}

	allocs := testing.AllocsPerRun(1000, func() {
		got = q.String()
	})
	if allocs != 1 {
		t.Errorf("allocs = %v; want 1", allocs)
	}
}

func TestICMP(t *testing.T) {
	var buf [64]byte
	var q QDecode

	t.Run("write header", func(t *testing.T) {
		header := ICMPHeader{
			IPHeader: IPHeader{
				SrcIP: NewIP(net.IPv4(1, 2, 3, 4)),
				DstIP: NewIP(net.IPv4(5, 6, 7, 8)),
				IPID:  0xdead,
			},
			Type: ICMPEchoRequest,
			Code: 0,
		}
		payload := []byte("icmp_payload")

		want := []byte{
			// IP header up to checksum
			0x45, 0x00, 0x00, 0x24, 0xde, 0xad, 0x00, 0x00, 0x40, 0x01, 0x8c, 0x18,
			// source ip
			0x01, 0x02, 0x03, 0x04,
			// destination ip
			0x05, 0x06, 0x07, 0x08,
			// ICMP header
			0x08, 0x00, 0x92, 0x6e,
			// payload
			0x69, 0x63, 0x6d, 0x70, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
		}

		n := copy(buf[ICMPDataOffset:], payload)
		got := buf[:ICMPDataOffset+n]
		err := WriteICMPHeader(header, got)

		if err != nil {
			t.Errorf("writing header: %v", err)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}
	})

	t.Run("parse packet", func(t *testing.T) {
		want := &QDecode{
			b:      buf[:],
			subofs: 20,

			IPProto: ICMP,
			SrcIP:   NewIP(net.IPv4(1, 2, 3, 4)),
			DstIP:   NewIP(net.IPv4(5, 6, 7, 8)),
		}
		got := &q

		got.Decode(buf[:])
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}
	})

	t.Run("generate response", func(t *testing.T) {
		want := []byte{
			// IP header up to checksum
			0x45, 0x00, 0x00, 0x24, 0x21, 0x52, 0x00, 0x00, 0x40, 0x01, 0x49, 0x74,
			// source ip
			0x05, 0x06, 0x07, 0x08,
			// destination ip
			0x01, 0x02, 0x03, 0x04,
			// ICMP header
			0x00, 0x00, 0x9a, 0x6e,
			// payload
			0x69, 0x63, 0x6d, 0x70, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
		}
		got := q.EchoRespond()

		if !bytes.Equal(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}
	})
}

func TestWriteUDPHeader(t *testing.T) {
	var buf [64]byte
	var q QDecode

	t.Run("write header", func(t *testing.T) {
		header := UDPHeader{
			IPHeader: IPHeader{
				SrcIP: NewIP(net.IPv4(1, 2, 3, 4)),
				DstIP: NewIP(net.IPv4(5, 6, 7, 8)),
				IPID:  0xdead,
			},
			SrcPort: 0xabcd,
			DstPort: 0xdcba,
		}
		payload := []byte("udp_payload")

		want := []byte{
			// IP header up to checksum
			0x45, 0x00, 0x00, 0x27, 0xde, 0xad, 0x00, 0x00, 0x40, 0x11, 0x8c, 0x05,
			// source ip
			0x01, 0x02, 0x03, 0x04,
			// destination ip
			0x05, 0x06, 0x07, 0x08,
			// UDP header
			0xab, 0xcd, 0xdc, 0xba, 0x00, 0x13, 0xc4, 0x38,
			// payload
			0x75, 0x64, 0x70, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
		}

		n := copy(buf[UDPDataOffset:], payload)
		got := buf[:UDPDataOffset+n]
		err := WriteUDPHeader(header, got)

		if err != nil {
			t.Errorf("writing header: %v", err)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}
	})

	t.Run("parse packet", func(t *testing.T) {
		want := &QDecode{
			b:      buf[:],
			subofs: 20,

			IPProto: UDP,
			SrcIP:   NewIP(net.IPv4(1, 2, 3, 4)),
			DstIP:   NewIP(net.IPv4(5, 6, 7, 8)),
			SrcPort: 0xabcd,
			DstPort: 0xdcba,
		}
		got := &q

		got.Decode(buf[:])
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}
	})

}

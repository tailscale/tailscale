// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlatbpf

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
)

func csum(b []byte, sum uint32) uint32 {
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func pseudo6(src, dst netip.Addr, proto uint8, n int) uint32 {
	s, d := src.As16(), dst.As16()
	return csum(d[:], csum(s[:], 0)) + uint32(n>>16) + uint32(n&0xffff) + uint32(proto)
}

func pseudo4(src, dst netip.Addr, proto uint8, n int) uint32 {
	s, d := src.As4(), dst.As4()
	return csum(d[:], csum(s[:], 0)) + uint32(proto) + uint32(n)
}

func csumOffset(proto uint8) int {
	switch proto {
	case 6:
		return 16
	case 17:
		return 6
	}
	return 2 // ICMP and ICMPv6
}

func tcpSeg(sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint32(b[4:], 1)
	b[12] = 5 << 4
	b[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(b[14:], 65535)
	copy(b[20:], payload)
	return b
}

func udpDgram(sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	copy(b[8:], payload)
	return b
}

func icmpMsg(typ uint8, id, seq uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], seq)
	copy(b[8:], payload)
	return b
}

// packet6 returns an Ethernet frame holding an IPv6 packet, with the L4 checksum filled in for TCP, UDP and ICMPv6.
func packet6(src, dst netip.Addr, proto uint8, l4 []byte) []byte {
	l4 = slices.Clone(l4)
	if proto == 6 || proto == 17 || proto == 58 {
		c := fold(csum(l4, pseudo6(src, dst, proto, len(l4))))
		if c == 0 && proto == 17 {
			c = 0xffff
		}
		binary.BigEndian.PutUint16(l4[csumOffset(proto):], c)
	}
	pkt := make([]byte, 14+40+len(l4))
	binary.BigEndian.PutUint16(pkt[12:], 0x86dd)
	ip := pkt[14:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
	ip[6], ip[7] = proto, 64
	s, d := src.As16(), dst.As16()
	copy(ip[8:], s[:])
	copy(ip[24:], d[:])
	copy(ip[40:], l4)
	return pkt
}

// packet4 returns an Ethernet frame holding an IPv4 packet, with both checksums filled in for TCP, UDP and ICMP.
func packet4(src, dst netip.Addr, proto uint8, l4 []byte) []byte {
	l4 = slices.Clone(l4)
	switch proto {
	case 6, 17:
		binary.BigEndian.PutUint16(l4[csumOffset(proto):], fold(csum(l4, pseudo4(src, dst, proto, len(l4)))))
	case 1:
		binary.BigEndian.PutUint16(l4[2:], fold(csum(l4, 0)))
	}
	pkt := make([]byte, 14+20+len(l4))
	binary.BigEndian.PutUint16(pkt[12:], 0x0800)
	ip := pkt[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
	ip[8], ip[9] = 64, proto
	s, d := src.As4(), dst.As4()
	copy(ip[12:], s[:])
	copy(ip[16:], d[:])
	binary.BigEndian.PutUint16(ip[10:], fold(csum(ip[:20], 0)))
	copy(ip[20:], l4)
	return pkt
}

// parse6 checks an Ethernet+IPv6 frame and its L4 checksum, and returns its fields.
func parse6(t *testing.T, pkt []byte) (src, dst netip.Addr, proto, hlim uint8, l4 []byte) {
	t.Helper()
	if et := binary.BigEndian.Uint16(pkt[12:]); et != 0x86dd {
		t.Fatalf("ethertype %#x; want IPv6", et)
	}
	ip := pkt[14:]
	if ip[0]>>4 != 6 {
		t.Fatalf("IP version %d; want 6", ip[0]>>4)
	}
	n := int(binary.BigEndian.Uint16(ip[4:]))
	src, dst = netip.AddrFrom16([16]byte(ip[8:24])), netip.AddrFrom16([16]byte(ip[24:40]))
	proto, hlim, l4 = ip[6], ip[7], ip[40:40+n]
	if fold(csum(l4, pseudo6(src, dst, proto, n))) != 0 {
		t.Errorf("bad L4 checksum (proto %d) after translation", proto)
	}
	return
}

// parse4 checks an Ethernet+IPv4 frame, its header checksum and its L4 checksum, and returns its fields.
func parse4(t *testing.T, pkt []byte) (src, dst netip.Addr, proto, ttl uint8, l4 []byte) {
	t.Helper()
	if et := binary.BigEndian.Uint16(pkt[12:]); et != 0x0800 {
		t.Fatalf("ethertype %#x; want IPv4", et)
	}
	ip := pkt[14:]
	if ip[0] != 0x45 {
		t.Fatalf("version/IHL %#x; want 0x45", ip[0])
	}
	if fold(csum(ip[:20], 0)) != 0 {
		t.Error("bad IPv4 header checksum after translation")
	}
	n := int(binary.BigEndian.Uint16(ip[2:])) - 20
	src, dst = netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20]))
	proto, ttl, l4 = ip[9], ip[8], ip[20:20+n]
	sum := uint32(0)
	if proto != 1 {
		sum = pseudo4(src, dst, proto, n)
	}
	if fold(csum(l4, sum)) != 0 {
		t.Errorf("bad L4 checksum (proto %d) after translation", proto)
	}
	return
}

// fragments6 splits an IPv6 packet built by packet6 into fragments carrying at most n bytes of its payload each.
func fragments6(pkt []byte, n int, id uint32) [][]byte {
	ip := pkt[14:]
	payload := ip[40:]
	var out [][]byte
	for off := 0; off < len(payload); off += n {
		end := min(off+n, len(payload))
		f := make([]byte, 14+40+8+end-off)
		copy(f, pkt[:14+40])
		binary.BigEndian.PutUint16(f[14+4:], uint16(8+end-off))
		f[14+6] = 44
		fh := f[14+40:]
		fh[0] = ip[6]
		offlg := uint16(off)
		if end < len(payload) {
			offlg |= 1
		}
		binary.BigEndian.PutUint16(fh[2:], offlg)
		binary.BigEndian.PutUint32(fh[4:], id)
		copy(f[14+40+8:], payload[off:end])
		out = append(out, f)
	}
	return out
}

// fragments4 splits an IPv4 packet built by packet4 into fragments carrying at most n bytes of its payload each.
func fragments4(pkt []byte, n int, id uint16) [][]byte {
	payload := pkt[14+20:]
	var out [][]byte
	for off := 0; off < len(payload); off += n {
		end := min(off+n, len(payload))
		f := make([]byte, 14+20+end-off)
		copy(f, pkt[:14+20])
		ip := f[14:]
		binary.BigEndian.PutUint16(ip[2:], uint16(20+end-off))
		binary.BigEndian.PutUint16(ip[4:], id)
		frag := uint16(off / 8)
		if end < len(payload) {
			frag |= 0x2000
		}
		binary.BigEndian.PutUint16(ip[6:], frag)
		ip[10], ip[11] = 0, 0
		binary.BigEndian.PutUint16(ip[10:], fold(csum(ip[:20], 0)))
		copy(f[14+20:], payload[off:end])
		out = append(out, f)
	}
	return out
}

// icmp4Error returns an ICMPv4 error message quoting q, an IPv4 frame from packet4, whole.
func icmp4Error(typ, code uint8, mtu uint16, q []byte) []byte {
	b := make([]byte, 8+len(q)-14)
	b[0], b[1] = typ, code
	binary.BigEndian.PutUint16(b[6:], mtu)
	copy(b[8:], q[14:])
	return b
}

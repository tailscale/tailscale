/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"math/rand"
	"net"
	"net/netip"
	"testing"
)

type testPairCommonBits struct {
	s1    []byte
	s2    []byte
	match uint8
}

func TestCommonBits(t *testing.T) {
	tests := []testPairCommonBits{
		{s1: []byte{1, 4, 53, 128}, s2: []byte{0, 0, 0, 0}, match: 7},
		{s1: []byte{0, 4, 53, 128}, s2: []byte{0, 0, 0, 0}, match: 13},
		{s1: []byte{0, 4, 53, 253}, s2: []byte{0, 4, 53, 252}, match: 31},
		{s1: []byte{192, 168, 1, 1}, s2: []byte{192, 169, 1, 1}, match: 15},
		{s1: []byte{65, 168, 1, 1}, s2: []byte{192, 169, 1, 1}, match: 0},
	}

	for _, p := range tests {
		v := commonBits(p.s1, p.s2)
		if v != p.match {
			t.Error(
				"For slice", p.s1, p.s2,
				"expected match", p.match,
				",but got", v,
			)
		}
	}
}

func benchmarkTrie(peerNumber, addressNumber, addressLength int, b *testing.B) {
	var trie *trieEntry
	var peers []*Peer
	root := parentIndirection{&trie, 2}

	rand.Seed(1)

	const AddressLength = 4

	for n := 0; n < peerNumber; n++ {
		peers = append(peers, &Peer{})
	}

	for n := 0; n < addressNumber; n++ {
		var addr [AddressLength]byte
		rand.Read(addr[:])
		cidr := uint8(rand.Uint32() % (AddressLength * 8))
		index := rand.Int() % peerNumber
		root.insert(addr[:], cidr, peers[index])
	}

	for n := 0; n < b.N; n++ {
		var addr [AddressLength]byte
		rand.Read(addr[:])
		trie.lookup(addr[:])
	}
}

func BenchmarkTrieIPv4Peers100Addresses1000(b *testing.B) {
	benchmarkTrie(100, 1000, net.IPv4len, b)
}

func BenchmarkTrieIPv4Peers10Addresses10(b *testing.B) {
	benchmarkTrie(10, 10, net.IPv4len, b)
}

func BenchmarkTrieIPv6Peers100Addresses1000(b *testing.B) {
	benchmarkTrie(100, 1000, net.IPv6len, b)
}

func BenchmarkTrieIPv6Peers10Addresses10(b *testing.B) {
	benchmarkTrie(10, 10, net.IPv6len, b)
}

/* Test ported from kernel implementation:
 * selftest/allowedips.h
 */
func TestTrieIPv4(t *testing.T) {
	a := &Peer{}
	b := &Peer{}
	c := &Peer{}
	d := &Peer{}
	e := &Peer{}
	g := &Peer{}
	h := &Peer{}

	var allowedIPs AllowedIPs

	insert := func(peer *Peer, a, b, c, d byte, cidr uint8) {
		allowedIPs.Insert(netip.PrefixFrom(netip.AddrFrom4([4]byte{a, b, c, d}), int(cidr)), peer)
	}

	assertEQ := func(peer *Peer, a, b, c, d byte) {
		p := allowedIPs.Lookup([]byte{a, b, c, d})
		if p != peer {
			t.Error("Assert EQ failed")
		}
	}

	assertNEQ := func(peer *Peer, a, b, c, d byte) {
		p := allowedIPs.Lookup([]byte{a, b, c, d})
		if p == peer {
			t.Error("Assert NEQ failed")
		}
	}

	insert(a, 192, 168, 4, 0, 24)
	insert(b, 192, 168, 4, 4, 32)
	insert(c, 192, 168, 0, 0, 16)
	insert(d, 192, 95, 5, 64, 27)
	insert(c, 192, 95, 5, 65, 27)
	insert(e, 0, 0, 0, 0, 0)
	insert(g, 64, 15, 112, 0, 20)
	insert(h, 64, 15, 123, 211, 25)
	insert(a, 10, 0, 0, 0, 25)
	insert(b, 10, 0, 0, 128, 25)
	insert(a, 10, 1, 0, 0, 30)
	insert(b, 10, 1, 0, 4, 30)
	insert(c, 10, 1, 0, 8, 29)
	insert(d, 10, 1, 0, 16, 29)

	assertEQ(a, 192, 168, 4, 20)
	assertEQ(a, 192, 168, 4, 0)
	assertEQ(b, 192, 168, 4, 4)
	assertEQ(c, 192, 168, 200, 182)
	assertEQ(c, 192, 95, 5, 68)
	assertEQ(e, 192, 95, 5, 96)
	assertEQ(g, 64, 15, 116, 26)
	assertEQ(g, 64, 15, 127, 3)

	insert(a, 1, 0, 0, 0, 32)
	insert(a, 64, 0, 0, 0, 32)
	insert(a, 128, 0, 0, 0, 32)
	insert(a, 192, 0, 0, 0, 32)
	insert(a, 255, 0, 0, 0, 32)

	assertEQ(a, 1, 0, 0, 0)
	assertEQ(a, 64, 0, 0, 0)
	assertEQ(a, 128, 0, 0, 0)
	assertEQ(a, 192, 0, 0, 0)
	assertEQ(a, 255, 0, 0, 0)

	allowedIPs.RemoveByPeer(a)

	assertNEQ(a, 1, 0, 0, 0)
	assertNEQ(a, 64, 0, 0, 0)
	assertNEQ(a, 128, 0, 0, 0)
	assertNEQ(a, 192, 0, 0, 0)
	assertNEQ(a, 255, 0, 0, 0)

	allowedIPs.RemoveByPeer(a)
	allowedIPs.RemoveByPeer(b)
	allowedIPs.RemoveByPeer(c)
	allowedIPs.RemoveByPeer(d)
	allowedIPs.RemoveByPeer(e)
	allowedIPs.RemoveByPeer(g)
	allowedIPs.RemoveByPeer(h)
	if allowedIPs.IPv4 != nil || allowedIPs.IPv6 != nil {
		t.Error("Expected removing all the peers to empty trie, but it did not")
	}

	insert(a, 192, 168, 0, 0, 16)
	insert(a, 192, 168, 0, 0, 24)

	allowedIPs.RemoveByPeer(a)

	assertNEQ(a, 192, 168, 0, 1)
}

/* Test ported from kernel implementation:
 * selftest/allowedips.h
 */
func TestTrieIPv6(t *testing.T) {
	a := &Peer{}
	b := &Peer{}
	c := &Peer{}
	d := &Peer{}
	e := &Peer{}
	f := &Peer{}
	g := &Peer{}
	h := &Peer{}

	var allowedIPs AllowedIPs

	expand := func(a uint32) []byte {
		var out [4]byte
		out[0] = byte(a >> 24 & 0xff)
		out[1] = byte(a >> 16 & 0xff)
		out[2] = byte(a >> 8 & 0xff)
		out[3] = byte(a & 0xff)
		return out[:]
	}

	insert := func(peer *Peer, a, b, c, d uint32, cidr uint8) {
		var addr []byte
		addr = append(addr, expand(a)...)
		addr = append(addr, expand(b)...)
		addr = append(addr, expand(c)...)
		addr = append(addr, expand(d)...)
		allowedIPs.Insert(netip.PrefixFrom(netip.AddrFrom16(*(*[16]byte)(addr)), int(cidr)), peer)
	}

	assertEQ := func(peer *Peer, a, b, c, d uint32) {
		var addr []byte
		addr = append(addr, expand(a)...)
		addr = append(addr, expand(b)...)
		addr = append(addr, expand(c)...)
		addr = append(addr, expand(d)...)
		p := allowedIPs.Lookup(addr)
		if p != peer {
			t.Error("Assert EQ failed")
		}
	}

	insert(d, 0x26075300, 0x60006b00, 0, 0xc05f0543, 128)
	insert(c, 0x26075300, 0x60006b00, 0, 0, 64)
	insert(e, 0, 0, 0, 0, 0)
	insert(f, 0, 0, 0, 0, 0)
	insert(g, 0x24046800, 0, 0, 0, 32)
	insert(h, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef, 64)
	insert(a, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef, 128)
	insert(c, 0x24446800, 0x40e40800, 0xdeaebeef, 0xdefbeef, 128)
	insert(b, 0x24446800, 0xf0e40800, 0xeeaebeef, 0, 98)

	assertEQ(d, 0x26075300, 0x60006b00, 0, 0xc05f0543)
	assertEQ(c, 0x26075300, 0x60006b00, 0, 0xc02e01ee)
	assertEQ(f, 0x26075300, 0x60006b01, 0, 0)
	assertEQ(g, 0x24046800, 0x40040806, 0, 0x1006)
	assertEQ(g, 0x24046800, 0x40040806, 0x1234, 0x5678)
	assertEQ(f, 0x240467ff, 0x40040806, 0x1234, 0x5678)
	assertEQ(f, 0x24046801, 0x40040806, 0x1234, 0x5678)
	assertEQ(h, 0x24046800, 0x40040800, 0x1234, 0x5678)
	assertEQ(h, 0x24046800, 0x40040800, 0, 0)
	assertEQ(h, 0x24046800, 0x40040800, 0x10101010, 0x10101010)
	assertEQ(a, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef)
}

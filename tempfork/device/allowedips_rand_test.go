/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"math/rand"
	"net"
	"net/netip"
	"sort"
	"testing"
)

const (
	NumberOfPeers        = 100
	NumberOfPeerRemovals = 4
	NumberOfAddresses    = 250
	NumberOfTests        = 10000
)

type SlowNode struct {
	peer *Peer
	cidr uint8
	bits []byte
}

type SlowRouter []*SlowNode

func (r SlowRouter) Len() int {
	return len(r)
}

func (r SlowRouter) Less(i, j int) bool {
	return r[i].cidr > r[j].cidr
}

func (r SlowRouter) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r SlowRouter) Insert(addr []byte, cidr uint8, peer *Peer) SlowRouter {
	for _, t := range r {
		if t.cidr == cidr && commonBits(t.bits, addr) >= cidr {
			t.peer = peer
			t.bits = addr
			return r
		}
	}
	r = append(r, &SlowNode{
		cidr: cidr,
		bits: addr,
		peer: peer,
	})
	sort.Sort(r)
	return r
}

func (r SlowRouter) Lookup(addr []byte) *Peer {
	for _, t := range r {
		common := commonBits(t.bits, addr)
		if common >= t.cidr {
			return t.peer
		}
	}
	return nil
}

func (r SlowRouter) RemoveByPeer(peer *Peer) SlowRouter {
	n := 0
	for _, x := range r {
		if x.peer != peer {
			r[n] = x
			n++
		}
	}
	return r[:n]
}

func TestTrieRandom(t *testing.T) {
	var slow4, slow6 SlowRouter
	var peers []*Peer
	var allowedIPs AllowedIPs

	rand.Seed(1)

	for n := 0; n < NumberOfPeers; n++ {
		peers = append(peers, &Peer{})
	}

	for n := 0; n < NumberOfAddresses; n++ {
		var addr4 [4]byte
		rand.Read(addr4[:])
		cidr := uint8(rand.Intn(32) + 1)
		index := rand.Intn(NumberOfPeers)
		allowedIPs.Insert(netip.PrefixFrom(netip.AddrFrom4(addr4), int(cidr)), peers[index])
		slow4 = slow4.Insert(addr4[:], cidr, peers[index])

		var addr6 [16]byte
		rand.Read(addr6[:])
		cidr = uint8(rand.Intn(128) + 1)
		index = rand.Intn(NumberOfPeers)
		allowedIPs.Insert(netip.PrefixFrom(netip.AddrFrom16(addr6), int(cidr)), peers[index])
		slow6 = slow6.Insert(addr6[:], cidr, peers[index])
	}

	var p int
	for p = 0; ; p++ {
		for n := 0; n < NumberOfTests; n++ {
			var addr4 [4]byte
			rand.Read(addr4[:])
			peer1 := slow4.Lookup(addr4[:])
			peer2 := allowedIPs.Lookup(addr4[:])
			if peer1 != peer2 {
				t.Errorf("Trie did not match naive implementation, for %v: want %p, got %p", net.IP(addr4[:]), peer1, peer2)
			}

			var addr6 [16]byte
			rand.Read(addr6[:])
			peer1 = slow6.Lookup(addr6[:])
			peer2 = allowedIPs.Lookup(addr6[:])
			if peer1 != peer2 {
				t.Errorf("Trie did not match naive implementation, for %v: want %p, got %p", net.IP(addr6[:]), peer1, peer2)
			}
		}
		if p >= len(peers) || p >= NumberOfPeerRemovals {
			break
		}
		allowedIPs.RemoveByPeer(peers[p])
		slow4 = slow4.RemoveByPeer(peers[p])
		slow6 = slow6.RemoveByPeer(peers[p])
	}
	for ; p < len(peers); p++ {
		allowedIPs.RemoveByPeer(peers[p])
	}

	if allowedIPs.IPv4 != nil || allowedIPs.IPv6 != nil {
		t.Error("Failed to remove all nodes from trie by peer")
	}
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ippool

import (
	"math"
	"math/big"
	"net/netip"
	"testing"

	"go4.org/netipx"
	"tailscale.com/util/must"
)

func TestV4ToNum(t *testing.T) {
	cases := []struct {
		addr netip.Addr
		num  uint32
	}{
		{netip.MustParseAddr("0.0.0.0"), 0},
		{netip.MustParseAddr("255.255.255.255"), 0xffffffff},
		{netip.MustParseAddr("8.8.8.8"), 0x08080808},
		{netip.MustParseAddr("192.168.0.1"), 0xc0a80001},
		{netip.MustParseAddr("10.0.0.1"), 0x0a000001},
		{netip.MustParseAddr("172.16.0.1"), 0xac100001},
		{netip.MustParseAddr("100.64.0.1"), 0x64400001},
	}

	for _, tc := range cases {
		num := v4ToNum(tc.addr)
		if num != tc.num {
			t.Errorf("addrNum(%v) = %d, want %d", tc.addr, num, tc.num)
		}
		if numToV4(num) != tc.addr {
			t.Errorf("numToV4(%d) = %v, want %v", num, numToV4(num), tc.addr)
		}
	}

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic")
			}
		}()

		v4ToNum(netip.MustParseAddr("::1"))
	}()
}

func TestAddrIndex(t *testing.T) {
	builder := netipx.IPSetBuilder{}
	builder.AddRange(netipx.MustParseIPRange("10.0.0.1-10.0.0.5"))
	builder.AddRange(netipx.MustParseIPRange("192.168.0.1-192.168.0.10"))
	ipset := must.Get(builder.IPSet())

	indexCases := []struct {
		addr  netip.Addr
		index int
	}{
		{netip.MustParseAddr("10.0.0.1"), 0},
		{netip.MustParseAddr("10.0.0.2"), 1},
		{netip.MustParseAddr("10.0.0.3"), 2},
		{netip.MustParseAddr("10.0.0.4"), 3},
		{netip.MustParseAddr("10.0.0.5"), 4},
		{netip.MustParseAddr("192.168.0.1"), 5},
		{netip.MustParseAddr("192.168.0.5"), 9},
		{netip.MustParseAddr("192.168.0.10"), 14},
		{netip.MustParseAddr("172.16.0.1"), -1}, // Not in set
	}

	for _, tc := range indexCases {
		index := indexOfAddr(tc.addr, ipset)
		if index != tc.index {
			t.Errorf("indexOfAddr(%v) = %d, want %d", tc.addr, index, tc.index)
		}
		if tc.index == -1 {
			continue
		}
		addr := addrAtIndex(tc.index, ipset)
		if addr != tc.addr {
			t.Errorf("addrAtIndex(%d) = %v, want %v", tc.index, addr, tc.addr)
		}
	}
}

func TestAllocAddr(t *testing.T) {
	builder := netipx.IPSetBuilder{}
	builder.AddRange(netipx.MustParseIPRange("10.0.0.1-10.0.0.5"))
	builder.AddRange(netipx.MustParseIPRange("192.168.0.1-192.168.0.10"))
	ipset := must.Get(builder.IPSet())

	allocated := new(big.Int)
	for range 15 {
		addr := allocAddr(ipset, allocated)
		if !addr.IsValid() {
			t.Errorf("allocAddr() = invalid, want valid")
		}
		if !ipset.Contains(addr) {
			t.Errorf("allocAddr() = %v, not in set", addr)
		}
	}
	addr := allocAddr(ipset, allocated)
	if addr.IsValid() {
		t.Errorf("allocAddr() = %v, want invalid", addr)
	}
	wantAddr := netip.MustParseAddr("10.0.0.2")
	allocated.SetBit(allocated, indexOfAddr(wantAddr, ipset), 0)
	addr = allocAddr(ipset, allocated)
	if addr != wantAddr {
		t.Errorf("allocAddr() = %v, want %v", addr, wantAddr)
	}
}

func TestLeastZeroBit(t *testing.T) {
	cases := []struct {
		num  uint
		want int
	}{
		{math.MaxUint, -1},
		{0, 0},
		{0b01, 1},
		{0b11, 2},
		{0b111, 3},
		{math.MaxUint, -1},
		{math.MaxUint - 1, 0},
	}
	if math.MaxUint == math.MaxUint64 {
		cases = append(cases, []struct {
			num  uint
			want int
		}{
			{math.MaxUint >> 1, 63},
		}...)
	} else {
		cases = append(cases, []struct {
			num  uint
			want int
		}{
			{math.MaxUint >> 1, 31},
		}...)
	}

	for _, tc := range cases {
		got := leastZeroBit(tc.num)
		if got != tc.want {
			t.Errorf("leastZeroBit(%b) = %d, want %d", tc.num, got, tc.want)
		}
	}
}

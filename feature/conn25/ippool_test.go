// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"errors"
	"math"
	"net/netip"
	"testing"

	"go4.org/netipx"
	"tailscale.com/util/must"
)

func TestNext(t *testing.T) {
	a := ipSetIterator{}
	_, err := a.next()
	if !errors.Is(err, errPoolExhausted) {
		t.Fatalf("expected errPoolExhausted, got %v", err)
	}

	var isb netipx.IPSetBuilder
	ipset := must.Get(isb.IPSet())
	b := newIPPool(ipset)
	_, err = b.next()
	if !errors.Is(err, errPoolExhausted) {
		t.Fatalf("expected errPoolExhausted, got %v", err)
	}

	isb.AddRange(netipx.IPRangeFrom(netip.MustParseAddr("192.168.0.0"), netip.MustParseAddr("192.168.0.2")))
	isb.AddRange(netipx.IPRangeFrom(netip.MustParseAddr("200.0.0.0"), netip.MustParseAddr("200.0.0.0")))
	isb.AddRange(netipx.IPRangeFrom(netip.MustParseAddr("201.0.0.0"), netip.MustParseAddr("201.0.0.1")))
	ipset = must.Get(isb.IPSet())
	c := newIPPool(ipset)
	expected := []string{
		"192.168.0.0",
		"192.168.0.1",
		"192.168.0.2",
		"200.0.0.0",
		"201.0.0.0",
		"201.0.0.1",
	}
	for i, want := range expected {
		addr, err := c.next()
		if err != nil {
			t.Fatal(err)
		}
		if addr != netip.MustParseAddr(want) {
			t.Fatalf("next call %d want: %s, got: %v", i, want, addr)
		}
	}
	_, err = c.next()
	if !errors.Is(err, errPoolExhausted) {
		t.Fatalf("expected errPoolExhausted, got %v", err)
	}
	_, err = c.next()
	if !errors.Is(err, errPoolExhausted) {
		t.Fatalf("expected errPoolExhausted, got %v", err)
	}
}

// TestReturnAddr tests that if a pool is exhausted, an address can be returned to the
// pool, and then that address will be handed out again.
func TestReturnAddr(t *testing.T) {
	addrString := "192.168.0.0"
	// There's an IPPool with one address in it.
	var isb netipx.IPSetBuilder
	isb.AddRange(netipx.IPRangeFrom(netip.MustParseAddr(addrString), netip.MustParseAddr(addrString)))
	ipset := must.Get(isb.IPSet())
	ipp := newIPPool(ipset)
	// The first time we call next we get the address.
	addr, err := ipp.next()
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if addr != netip.MustParseAddr(addrString) {
		t.Fatalf("want %v, got %v", addrString, addr)
	}
	// The second time we call next we get errPoolExhausted
	_, err = ipp.next()
	if !errors.Is(err, errPoolExhausted) {
		t.Fatalf("expected errPoolExhausted, got %v", err)
	}
	// Return the addr to the pool
	err = ipp.returnAddr(netip.MustParseAddr(addrString))
	if err != nil {
		t.Fatal(err)
	}
	// It's not possible to return addresses that are already in the pool.
	err = ipp.returnAddr(netip.MustParseAddr(addrString))
	if !errors.Is(err, errAddrExists) {
		t.Fatalf("want errAddrExists, got: %v", err)
	}
	// When we call next we get the returned addr
	addrAfterReturn, err := ipp.next()
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if addrAfterReturn != netip.MustParseAddr(addrString) {
		t.Fatalf("want %v, got %v", addrString, addrAfterReturn)
	}
	// You can't return addresses that aren't from the pool.
	err = ipp.returnAddr(netip.MustParseAddr("100.100.100.0"))
	if !errors.Is(err, errNotOurAddress) {
		t.Fatalf("want errNotOurAddress, got: %v", err)
	}
}

func expectAddrNext(t *testing.T, ipp *ippool, addrString string) {
	t.Helper()
	got, err := ipp.next()
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	want := netip.MustParseAddr(addrString)
	if want != got {
		t.Fatalf("want %v; got %v", want, got)
	}
}

func expectErrPoolExhaustedNext(t *testing.T, ipp *ippool) {
	t.Helper()
	_, err := ipp.next()
	if !errors.Is(err, errPoolExhausted) {
		t.Fatalf("expected errPoolExhausted; got %v", err)
	}
}

// TestGettingReturnedAddresses tests that when addresses are returned to the IP Pool
// they are then handed out in the order they were returned.
func TestGettingReturnedAddresses(t *testing.T) {
	var isb netipx.IPSetBuilder
	isb.AddRange(netipx.IPRangeFrom(netip.MustParseAddr("192.168.0.0"), netip.MustParseAddr("192.168.0.4")))
	ipset := must.Get(isb.IPSet())
	ipp := newIPPool(ipset)
	expectAddrNext(t, ipp, "192.168.0.0")
	expectAddrNext(t, ipp, "192.168.0.1")
	expectAddrNext(t, ipp, "192.168.0.2")
	expectAddrNext(t, ipp, "192.168.0.3")
	expectAddrNext(t, ipp, "192.168.0.4")
	expectErrPoolExhaustedNext(t, ipp)
	ipp.returnAddr(netip.MustParseAddr("192.168.0.2"))
	ipp.returnAddr(netip.MustParseAddr("192.168.0.4"))
	expectAddrNext(t, ipp, "192.168.0.2")
	expectAddrNext(t, ipp, "192.168.0.4")
	expectErrPoolExhaustedNext(t, ipp)
}

func TestIPPoolReconfig(t *testing.T) {
	var isb netipx.IPSetBuilder
	isb.AddRange(netipx.IPRangeFrom(netip.MustParseAddr("192.168.0.0"), netip.MustParseAddr("192.168.0.4")))
	ipsetOne := must.Get(isb.IPSet())
	ipsetOneClone := must.Get(isb.IPSet())
	isb = netipx.IPSetBuilder{}
	isb.AddRange(netipx.IPRangeFrom(netip.MustParseAddr("192.168.0.7"), netip.MustParseAddr("192.168.0.10")))
	ipsetTwo := must.Get(isb.IPSet())

	var ipp *ippool
	ipp = ipp.reconfig(ipsetOne)
	if ipp.ipSet != ipsetOne {
		t.Fatalf("want %v, got %v", ipsetOne, ipp.ipSet)
	}
	expectAddrNext(t, ipp, "192.168.0.0")

	// check that we don't lose iterator state when we reconfig with the same ranges
	expectAddrNext(t, ipp, "192.168.0.1")
	ipp.returnAddr(netip.MustParseAddr("192.168.0.1"))
	ipp = ipp.reconfig(ipsetOneClone)
	expectAddrNext(t, ipp, "192.168.0.2")

	// when we reconfig with different ranges, we only hand out addresses from the new ranges
	ipp = ipp.reconfig(ipsetTwo)
	if ipp.ipSet != ipsetTwo {
		t.Fatalf("want %v, got %v", ipsetTwo, ipp.ipSet)
	}
	expectAddrNext(t, ipp, "192.168.0.7")
	expectAddrNext(t, ipp, "192.168.0.8")
	expectAddrNext(t, ipp, "192.168.0.9")
	expectAddrNext(t, ipp, "192.168.0.10")
	expectErrPoolExhaustedNext(t, ipp)

	// but we have not lost track of the fact that the old addresses are in use
	if !ipp.inUse.Contains(netip.MustParseAddr("192.168.0.0")) {
		t.Fatalf("expected inUse to still have the address")
	}

	// old addresses can be returned
	ipp.returnAddr(netip.MustParseAddr("192.168.0.0"))

	// but they are not handed out again
	expectErrPoolExhaustedNext(t, ipp)
	if ipp.inUse.Contains(netip.MustParseAddr("192.168.0.0")) {
		t.Fatalf("expected inUse to no longer have the address")
	}

	// returning addresses from the new ranges works as normal
	ipp.returnAddr(netip.MustParseAddr("192.168.0.9"))
	expectAddrNext(t, ipp, "192.168.0.9")
}

func TestIPPoolCapacity(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   int64
	}{
		{"ipv4-slash-30", "100.64.0.0/30", 4},
		{"ipv4-slash-24", "100.64.0.0/24", 256},
		{"ipv4-single", "100.64.0.1/32", 1},
		{"ipv6-slash-120", "fd7a::/120", 256},
		// 2^62 is the largest power of two below math.MaxInt64; not clamped.
		{"ipv6-slash-66-not-clamped", "fd7a::/66", 1 << 62},
		// 2^63 overflows int64, so it clamps.
		{"ipv6-slash-65-clamps", "fd7a::/65", math.MaxInt64},
		{"ipv6-slash-64-clamps", "fd7a::/64", math.MaxInt64},
		{"ipv6-default-clamps", "::/0", math.MaxInt64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipp := newIPPool(mustIPSetFromPrefix(tt.prefix))
			if got := ipp.capacity(); got != tt.want {
				t.Errorf("capacity(%s) = %d, want %d", tt.prefix, got, tt.want)
			}
		})
	}

	t.Run("multi-prefix-sum-overflows-clamps", func(t *testing.T) {
		b := &netipx.IPSetBuilder{}
		b.AddPrefix(netip.MustParsePrefix("fd7a::/66"))            // 2^62 +
		b.AddPrefix(netip.MustParsePrefix("fd7a:0:0:0:8000::/66")) // 2^62 = 2^63 (1 more than MaxInt64)
		set, err := b.IPSet()
		if err != nil {
			t.Fatal(err)
		}
		if got := newIPPool(set).capacity(); got != math.MaxInt64 {
			t.Errorf("capacity() = %d, want %d", got, int64(math.MaxInt64))
		}
	})

	t.Run("nil-and-uninitialized", func(t *testing.T) {
		var nilPool *ippool
		if got := nilPool.capacity(); got != 0 {
			t.Errorf("nil pool capacity() = %d, want 0", got)
		}
		// newIPPool(nil) returns a non-nil pool with a nil ipSet.
		if got := newIPPool(nil).capacity(); got != 0 {
			t.Errorf("uninitialized pool capacity() = %d, want 0", got)
		}
	})
}

func TestIPPoolInUseCount(t *testing.T) {
	t.Run("counts-handed-out", func(t *testing.T) {
		ipp := newIPPool(mustIPSetFromPrefix("100.64.0.0/29")) // 8 addresses
		if got := ipp.inUseCount(); got != 0 {
			t.Fatalf("fresh pool inUseCount() = %d, want 0", got)
		}
		a1 := must.Get(ipp.next())
		must.Get(ipp.next())
		if got := ipp.inUseCount(); got != 2 {
			t.Fatalf("after 2 next() inUseCount() = %d, want 2", got)
		}
		if err := ipp.returnAddr(a1); err != nil {
			t.Fatal(err)
		}
		if got := ipp.inUseCount(); got != 1 {
			t.Fatalf("after returnAddr inUseCount() = %d, want 1", got)
		}
	})

	t.Run("nil-and-uninitialized", func(t *testing.T) {
		var nilPool *ippool
		if got := nilPool.inUseCount(); got != 0 {
			t.Errorf("nil pool inUseCount() = %d, want 0", got)
		}
		// newIPPool(nil) returns a non-nil pool with a nil inUse set.
		if got := newIPPool(nil).inUseCount(); got != 0 {
			t.Errorf("uninitialized pool inUseCount() = %d, want 0", got)
		}
	})
}

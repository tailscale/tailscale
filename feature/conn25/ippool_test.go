// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"errors"
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

// TestGettingReturnedAddresses tests that when addresses are returned to the IP Pool
// they are then handed out in the order they were returned.
func TestGettingReturnedAddresses(t *testing.T) {
	var isb netipx.IPSetBuilder
	isb.AddRange(netipx.IPRangeFrom(netip.MustParseAddr("192.168.0.0"), netip.MustParseAddr("192.168.0.4")))
	ipset := must.Get(isb.IPSet())
	ipp := newIPPool(ipset)
	expectAddrNext := func(addrString string) {
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
	expectErrPoolExhaustedNext := func() {
		t.Helper()
		_, err := ipp.next()
		if !errors.Is(err, errPoolExhausted) {
			t.Fatalf("expected errPoolExhausted; got %v", err)
		}
	}
	expectAddrNext("192.168.0.0")
	expectAddrNext("192.168.0.1")
	expectAddrNext("192.168.0.2")
	expectAddrNext("192.168.0.3")
	expectAddrNext("192.168.0.4")
	expectErrPoolExhaustedNext()
	ipp.returnAddr(netip.MustParseAddr("192.168.0.2"))
	ipp.returnAddr(netip.MustParseAddr("192.168.0.4"))
	expectAddrNext("192.168.0.2")
	expectAddrNext("192.168.0.4")
	expectErrPoolExhaustedNext()
}

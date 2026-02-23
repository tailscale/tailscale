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
	a := ippool{}
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

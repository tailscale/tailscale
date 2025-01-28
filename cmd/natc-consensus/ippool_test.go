package main

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

func TestV6V4(t *testing.T) {
	c := connector{
		v6ULA: ula(uint16(1)),
	}

	tests := [][]string{
		[]string{"100.64.0.0", "fd7a:115c:a1e0:a99c:1:0:6440:0"},
		[]string{"0.0.0.0", "fd7a:115c:a1e0:a99c:1::"},
		[]string{"255.255.255.255", "fd7a:115c:a1e0:a99c:1:0:ffff:ffff"},
	}

	for i, test := range tests {
		// to v6
		v6 := c.v6ForV4(netip.MustParseAddr(test[0]))
		want := netip.MustParseAddr(test[1])
		if v6 != want {
			t.Fatalf("test %d: want: %v, got: %v", i, want, v6)
		}

		// to v4
		v4 := v4ForV6(netip.MustParseAddr(test[1]))
		want = netip.MustParseAddr(test[0])
		if v4 != want {
			t.Fatalf("test %d: want: %v, got: %v", i, want, v4)
		}
	}
}

func TestIPForDomain(t *testing.T) {
	pfx := netip.MustParsePrefix("100.64.0.0/16")
	ipp := fsm{
		v4Ranges: []netip.Prefix{pfx},
		dnsAddr:  netip.MustParseAddr("100.64.0.0"),
	}
	now := time.Now()
	deadline := now.Add(-2 * time.Hour)

	a, err := ipp.applyCheckoutAddr(tailcfg.NodeID(1), "example.com", deadline, now)
	if err != nil {
		t.Fatal(err)
	}
	if !pfx.Contains(a) {
		t.Fatalf("expected %v to be in the prefix %v", a, pfx)
	}

	b, err := ipp.applyCheckoutAddr(tailcfg.NodeID(1), "a.example.com", deadline, now)
	if err != nil {
		t.Fatal(err)
	}
	if !pfx.Contains(b) {
		t.Fatalf("expected %v to be in the prefix %v", b, pfx)
	}
	if b == a {
		t.Fatalf("same address issued twice %v, %v", a, b)
	}

	c, err := ipp.applyCheckoutAddr(tailcfg.NodeID(1), "example.com", deadline, now)
	if err != nil {
		t.Fatal(err)
	}
	if c != a {
		t.Fatalf("expected %v to be remembered as the addr for example.com, but got %v", a, c)
	}
}

func TestDomainForIP(t *testing.T) {
	pfx := netip.MustParsePrefix("100.64.0.0/16")
	sm := fsm{
		v4Ranges: []netip.Prefix{pfx},
		dnsAddr:  netip.MustParseAddr("100.64.0.0"),
	}
	ipp := (*ipPool)(&sm)
	nid := tailcfg.NodeID(1)
	domain := "example.com"
	now := time.Now()
	deadline := now.Add(-2 * time.Hour)

	d := ipp.DomainForIP(nid, netip.MustParseAddr("100.64.0.1"), now)
	if d != "" {
		t.Fatalf("expected an empty string if the addr is not found but got %s", d)
	}
	a, err := sm.applyCheckoutAddr(nid, domain, deadline, now)
	if err != nil {
		t.Fatal(err)
	}
	d2 := ipp.DomainForIP(nid, a, now)
	if d2 != domain {
		t.Fatalf("expected %s but got %s", domain, d2)
	}
}

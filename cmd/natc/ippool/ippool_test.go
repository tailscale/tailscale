// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ippool

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/util/must"
)

func TestIPPoolExhaustion(t *testing.T) {
	smallPrefix := netip.MustParsePrefix("100.64.1.0/30") // Only 4 IPs: .0, .1, .2, .3
	var ipsb netipx.IPSetBuilder
	ipsb.AddPrefix(smallPrefix)
	addrPool := must.Get(ipsb.IPSet())
	v6ULA := netip.MustParsePrefix("fd7a:115c:a1e0:a99c:0001::/80")
	pool := IPPool{V6ULA: v6ULA, IPSet: addrPool}

	assignedIPs := make(map[netip.Addr]string)

	domains := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"}

	var errs []error

	from := tailcfg.NodeID(12345)

	for i := 0; i < 5; i++ {
		for _, domain := range domains {
			addrs, err := pool.IPForDomain(from, domain)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to get IP for domain %q: %w", domain, err))
				continue
			}

			for _, addr := range addrs {
				if d, ok := assignedIPs[addr]; ok {
					if d != domain {
						t.Errorf("IP %s reused for domain %q, previously assigned to %q", addr, domain, d)
					}
				} else {
					assignedIPs[addr] = domain
				}
			}
		}
	}

	for addr, domain := range assignedIPs {
		if addr.Is4() && !smallPrefix.Contains(addr) {
			t.Errorf("IP %s for domain %q not in expected range %s", addr, domain, smallPrefix)
		}
		if addr.Is6() && !v6ULA.Contains(addr) {
			t.Errorf("IP %s for domain %q not in expected range %s", addr, domain, v6ULA)
		}
	}

	// expect one error for each iteration with the 5th domain
	if len(errs) != 5 {
		t.Errorf("Expected 5 errors, got %d: %v", len(errs), errs)
	}
	for _, err := range errs {
		if !errors.Is(err, ErrNoIPsAvailable) {
			t.Errorf("generateDNSResponse() error = %v, want ErrNoIPsAvailable", err)
		}
	}
}

func TestIPPool(t *testing.T) {
	var ipsb netipx.IPSetBuilder
	ipsb.AddPrefix(netip.MustParsePrefix("100.64.1.0/24"))
	addrPool := must.Get(ipsb.IPSet())
	pool := IPPool{
		V6ULA: netip.MustParsePrefix("fd7a:115c:a1e0:a99c:0001::/80"),
		IPSet: addrPool,
	}
	from := tailcfg.NodeID(12345)
	addrs, err := pool.IPForDomain(from, "example.com")
	if err != nil {
		t.Fatalf("ipForDomain() error = %v", err)
	}

	if len(addrs) != 2 {
		t.Fatalf("ipForDomain() returned %d addresses, want 2", len(addrs))
	}

	v4 := addrs[0]
	v6 := addrs[1]

	if !v4.Is4() {
		t.Errorf("First address is not IPv4: %s", v4)
	}

	if !v6.Is6() {
		t.Errorf("Second address is not IPv6: %s", v6)
	}

	if !addrPool.Contains(v4) {
		t.Errorf("IPv4 address %s not in range %s", v4, addrPool)
	}

	domain, ok := pool.DomainForIP(from, v4)
	if !ok {
		t.Errorf("domainForIP(%s) not found", v4)
	} else if domain != "example.com" {
		t.Errorf("domainForIP(%s) = %s, want %s", v4, domain, "example.com")
	}

	domain, ok = pool.DomainForIP(from, v6)
	if !ok {
		t.Errorf("domainForIP(%s) not found", v6)
	} else if domain != "example.com" {
		t.Errorf("domainForIP(%s) = %s, want %s", v6, domain, "example.com")
	}

	addrs2, err := pool.IPForDomain(from, "example.com")
	if err != nil {
		t.Fatalf("ipForDomain() second call error = %v", err)
	}

	if !slices.Equal(addrs, addrs2) {
		t.Errorf("ipForDomain() second call = %v, want %v", addrs2, addrs)
	}
}

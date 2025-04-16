// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ippool

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/util/must"
)

func TestIPPoolExhaustion(t *testing.T) {
	smallPrefix := netip.MustParsePrefix("100.64.1.0/30") // Only 4 IPs: .0, .1, .2, .3
	var ipsb netipx.IPSetBuilder
	ipsb.AddPrefix(smallPrefix)
	addrPool := must.Get(ipsb.IPSet())
	pool := SingleMachineIPPool{IPSet: addrPool}

	assignedIPs := make(map[netip.Addr]string)

	domains := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"}

	var errs []error

	from := tailcfg.NodeID(12345)

	for i := 0; i < 5; i++ {
		for _, domain := range domains {
			addr, err := pool.IPForDomain(from, domain)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to get IP for domain %q: %w", domain, err))
				continue
			}

			if d, ok := assignedIPs[addr]; ok {
				if d != domain {
					t.Errorf("IP %s reused for domain %q, previously assigned to %q", addr, domain, d)
				}
			} else {
				assignedIPs[addr] = domain
			}
		}
	}

	for addr, domain := range assignedIPs {
		if addr.Is4() && !smallPrefix.Contains(addr) {
			t.Errorf("IP %s for domain %q not in expected range %s", addr, domain, smallPrefix)
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
	pool := SingleMachineIPPool{
		IPSet: addrPool,
	}
	from := tailcfg.NodeID(12345)
	addr, err := pool.IPForDomain(from, "example.com")
	if err != nil {
		t.Fatalf("ipForDomain() error = %v", err)
	}

	if !addr.IsValid() {
		t.Fatal("ipForDomain() returned an invalid address")
	}

	if !addr.Is4() {
		t.Errorf("Address is not IPv4: %s", addr)
	}

	if !addrPool.Contains(addr) {
		t.Errorf("IPv4 address %s not in range %s", addr, addrPool)
	}

	domain, ok := pool.DomainForIP(from, addr, time.Now())
	if !ok {
		t.Errorf("domainForIP(%s) not found", addr)
	} else if domain != "example.com" {
		t.Errorf("domainForIP(%s) = %s, want %s", addr, domain, "example.com")
	}

	addr2, err := pool.IPForDomain(from, "example.com")
	if err != nil {
		t.Fatalf("ipForDomain() second call error = %v", err)
	}

	if addr.Compare(addr2) != 0 {
		t.Errorf("ipForDomain() second call = %v, want %v", addr2, addr)
	}
}

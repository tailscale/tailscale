// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"tailscale.com/syncs"
)

func TestForEachAddr(t *testing.T) {
	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker)

	opts := ForEachAddrOpts{
		Logf:     t.Logf,
		Networks: []string{"ip4", "ip6"},
	}

	var (
		addr4_1 = netip.MustParseAddr("76.76.21.21")
		addr4_2 = netip.MustParseAddr("127.0.0.1")

		addr6_1 = netip.MustParseAddr("2600:9000:a602:b1e6:5b89:50a1:7cf7:67b8")
		addr6_2 = netip.MustParseAddr("2600:9000:a51d:27c1:6748:d035:a989:fb3c")
	)

	var resolverAddrs4, resolverAddrs6 syncs.AtomicValue[[]netip.Addr]
	resolverAddrs4.Store([]netip.Addr{addr4_1})
	resolverAddrs6.Store([]netip.Addr{addr6_1, addr6_2})

	opts.LookupNetIP = func(_ context.Context, network string, _ string) ([]netip.Addr, error) {
		if network == "ip4" {
			return resolverAddrs4.Load(), nil
		} else if network == "ip6" {
			return resolverAddrs6.Load(), nil
		}
		return nil, fmt.Errorf("unknown network %q", network)
	}

	var (
		mu         sync.Mutex // protects following
		registered []netip.Addr
	)
	newProbe := func(addr netip.Addr) []*Probe {
		// Called to register a new prober
		t.Logf("called to register new probe for %v", addr)

		mu.Lock()
		defer mu.Unlock()
		registered = append(registered, addr)

		// Return a probe that does nothing; we don't care about what this does.
		probe := p.Run(fmt.Sprintf("website/%s", addr), probeInterval, nil, FuncProbe(func(_ context.Context) error {
			return nil
		}))
		return []*Probe{probe}
	}

	fep := makeForEachAddr("tailscale.com", newProbe, opts)

	// Mimic a call from the prober; we do this ourselves instead of
	// calling it via p.Run so we know that the probe has actually run.
	ctx := context.Background()
	if err := fep.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}

	mu.Lock()
	wantAddrs := []netip.Addr{addr4_1, addr6_1, addr6_2}
	if !slices.Equal(registered, wantAddrs) {
		t.Errorf("got registered addrs %v; want %v", registered, wantAddrs)
	}
	mu.Unlock()

	// Now, update our IP addresses to force the prober to close and
	// re-create our probes.
	resolverAddrs4.Store([]netip.Addr{addr4_2})
	resolverAddrs6.Store([]netip.Addr{addr6_2})

	// Clear out our test data.
	mu.Lock()
	registered = nil
	mu.Unlock()

	// Run our individual prober again manually (so we don't have to wait
	// or coordinate with the created probers).
	if err := fep.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Ensure that we only registered our net-new address (addr4_2).
	mu.Lock()
	wantAddrs = []netip.Addr{addr4_2}
	if !slices.Equal(registered, wantAddrs) {
		t.Errorf("got registered addrs %v; want %v", registered, wantAddrs)
	}
	mu.Unlock()

	// Check that we don't have a probe for the addresses that we expect to
	// have been removed (addr4_1 and addr6_1).
	p.mu.Lock()
	for _, addr := range []netip.Addr{addr4_1, addr6_1} {
		_, ok := fep.probes[addr]
		if ok {
			t.Errorf("probe for %v still exists", addr)
		}
	}
	p.mu.Unlock()
}

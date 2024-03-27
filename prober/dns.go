// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"tailscale.com/types/logger"
)

// ForEachAddrOpts contains options for ForEachAddr. The zero value for all
// fields is valid unless stated otherwise.
type ForEachAddrOpts struct {
	// Logf is the logger to use for logging. If nil, no logging is done.
	Logf logger.Logf
	// Networks is the list of networks to resolve; if non-empty, it should
	// contain at least one of "ip", "ip4", or "ip6".
	//
	// If empty, "ip" is assumed.
	Networks []string
	// LookupNetIP is the function to use to resolve the hostname to one or
	// more IP addresses.
	//
	// If nil, net.DefaultResolver.LookupNetIP is used.
	LookupNetIP func(context.Context, string, string) ([]netip.Addr, error)
}

// ForEachAddr returns a Probe that resolves a given hostname into all
// available IP addresses, and then calls a function to create new Probes
// every time a new IP is discovered. The Probes returned will be closed if an
// IP address is no longer in the DNS record for the given hostname. This can
// be used to healthcheck every IP address that a hostname resolves to.
func ForEachAddr(host string, makeProbes func(netip.Addr) []*Probe, opts ForEachAddrOpts) ProbeClass {
	feap := makeForEachAddr(host, makeProbes, opts)
	return ProbeClass{
		Probe: feap.run,
		Class: "dns_each_addr",
	}
}

func makeForEachAddr(host string, makeProbes func(netip.Addr) []*Probe, opts ForEachAddrOpts) *forEachAddrProbe {
	if opts.Logf == nil {
		opts.Logf = logger.Discard
	}
	if len(opts.Networks) == 0 {
		opts.Networks = []string{"ip"}
	}
	if opts.LookupNetIP == nil {
		opts.LookupNetIP = net.DefaultResolver.LookupNetIP
	}

	return &forEachAddrProbe{
		logf:        opts.Logf,
		host:        host,
		networks:    opts.Networks,
		makeProbes:  makeProbes,
		lookupNetIP: opts.LookupNetIP,
		probes:      make(map[netip.Addr][]*Probe),
	}
}

type forEachAddrProbe struct {
	// inputs; immutable
	logf        logger.Logf
	host        string
	networks    []string
	makeProbes  func(netip.Addr) []*Probe
	lookupNetIP func(context.Context, string, string) ([]netip.Addr, error)

	// state
	mu     sync.Mutex // protects following
	probes map[netip.Addr][]*Probe
}

// run matches the ProbeFunc signature
func (f *forEachAddrProbe) run(ctx context.Context) error {
	var addrs []netip.Addr
	for _, network := range f.networks {
		naddrs, err := f.lookupNetIP(ctx, network, f.host)
		if err != nil {
			return fmt.Errorf("resolving %s addr for %q: %w", network, f.host, err)
		}
		addrs = append(addrs, naddrs...)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no addrs for %q", f.host)
	}

	// For each address, create a new probe if it doesn't already
	// exist in our probe map.
	f.mu.Lock()
	defer f.mu.Unlock()

	sawIPs := make(map[netip.Addr]bool)
	for _, addr := range addrs {
		sawIPs[addr] = true

		if _, ok := f.probes[addr]; ok {
			// Nothing to create
			continue
		}

		// Make a new probe, and add it to 'probes'; if the
		// function returns an empty list, we skip it.
		probes := f.makeProbes(addr)
		if len(probes) == 0 {
			continue
		}

		f.logf("adding %d new probes for %v", len(probes), addr)
		f.probes[addr] = probes
	}

	// Remove probes that we didn't see during this address resolution.
	for addr, probes := range f.probes {
		if !sawIPs[addr] {
			f.logf("removing %d probes for %v", len(probes), addr)

			// This IP is no longer in the DNS record. Close and remove all probes
			for _, probe := range probes {
				probe.Close()
			}
			delete(f.probes, addr)
		}
	}
	return nil
}

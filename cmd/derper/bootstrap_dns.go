// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"tailscale.com/net/dnsfallback/fallbacknames"
	"tailscale.com/syncs"
	"tailscale.com/util/mak"
	"tailscale.com/util/slicesx"
)

const refreshTimeout = time.Minute

type dnsEntryMap struct {
	IPs map[string][]net.IP
}

var (
	dnsCache           atomic.Pointer[dnsEntryMap]
	dnsCacheBytes      syncs.AtomicValue[[]byte] // of JSON
	bootstrapLookupMap syncs.Map[string, bool]
)

var (
	bootstrapDNSRequests = expvar.NewInt("counter_bootstrap_dns_requests")
	publishedDNSHits     = expvar.NewInt("counter_bootstrap_dns_published_hits")
	publishedDNSMisses   = expvar.NewInt("counter_bootstrap_dns_published_misses")
	unknownDNSNames      = expvar.NewInt("counter_bootstrap_dns_unknown_names")
)

func init() {
	expvar.Publish("counter_bootstrap_dns_queried_domains", expvar.Func(func() any {
		return bootstrapLookupMap.Len()
	}))
}

// bootstrapDNSNames returns the hostnames in the --bootstrap-dns-names flag.
func bootstrapDNSNames() []string {
	if *bootstrapDNS == "" {
		return nil
	}
	return strings.Split(*bootstrapDNS, ",")
}

// validateBootstrapDNSNames returns an error if any of the
// --bootstrap-dns-names hostnames isn't one that clients' DERP-based
// fallback DNS will ever ask for.
//
// We're slowly removing that fallback DNS mechanism, so names can be
// removed from the flag but new kinds of names can't be added.
// See https://github.com/tailscale/tailscale/issues/21028.
func validateBootstrapDNSNames() error {
	for _, name := range bootstrapDNSNames() {
		if !fallbacknames.IsTailscaleHost(name) {
			return fmt.Errorf("--bootstrap-dns-names entry %q is not a name clients' fallback DNS resolves (see tailscale.com/net/dnsfallback/fallbacknames)", name)
		}
	}
	return nil
}

func refreshBootstrapDNSLoop() {
	if *bootstrapDNS == "" {
		return
	}
	for {
		refreshBootstrapDNS()
		time.Sleep(10 * time.Minute)
	}
}

func refreshBootstrapDNS() {
	if *bootstrapDNS == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()
	dnsEntries := resolveList(ctx, bootstrapDNSNames())
	// Randomize the order of the IPs for each name to avoid the client biasing
	// to IPv6
	for _, vv := range dnsEntries.IPs {
		slicesx.Shuffle(vv)
	}
	j, err := json.MarshalIndent(dnsEntries.IPs, "", "\t")
	if err != nil {
		// leave the old values in place
		return
	}

	dnsCache.Store(dnsEntries)
	dnsCacheBytes.Store(j)
}

// resolveList resolves each of names.
func resolveList(ctx context.Context, names []string) *dnsEntryMap {
	ret := &dnsEntryMap{}

	var r net.Resolver
	for _, name := range names {
		addrs, err := r.LookupIP(ctx, "ip", name)
		if err != nil {
			log.Printf("bootstrap DNS lookup %q: %v", name, err)
			continue
		}
		mak.Set(&ret.IPs, name, addrs)
	}
	return ret
}

func handleBootstrapDNS(w http.ResponseWriter, r *http.Request) {
	bootstrapDNSRequests.Add(1)

	w.Header().Set("Content-Type", "application/json")
	// Bootstrap DNS requests occur cross-regions, and are randomized per
	// request, so keeping a connection open is pointlessly expensive.
	w.Header().Set("Connection", "close")

	// If we have a "q" query, track whether it's a name we publish and
	// whether we have IPs for it.
	if q := r.URL.Query().Get("q"); q != "" {
		bootstrapLookupMap.Store(q, true)
		if bootstrapLookupMap.Len() > 500 { // defensive
			bootstrapLookupMap.Clear()
		}
		m := dnsCache.Load()
		var inPub bool
		var ips []net.IP
		if m != nil {
			ips, inPub = m.IPs[q]
		}
		switch {
		case !inPub:
			unknownDNSNames.Add(1)
		case len(ips) > 0:
			publishedDNSHits.Add(1)
		default:
			publishedDNSMisses.Add(1)
		}
	}

	// Return the whole published set of cached DNS names. Clients pick
	// out the one they asked for.
	j := dnsCacheBytes.Load()
	w.Write(j)
}

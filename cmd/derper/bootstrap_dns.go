// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"expvar"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"tailscale.com/syncs"
)

const refreshTimeout = time.Minute

type dnsEntryMap map[string][]net.IP

var (
	dnsCache            syncs.AtomicValue[dnsEntryMap]
	dnsCacheBytes       syncs.AtomicValue[[]byte] // of JSON
	unpublishedDNSCache syncs.AtomicValue[dnsEntryMap]
)

var (
	bootstrapDNSRequests = expvar.NewInt("counter_bootstrap_dns_requests")
	publishedDNSHits     = expvar.NewInt("counter_bootstrap_dns_published_hits")
	publishedDNSMisses   = expvar.NewInt("counter_bootstrap_dns_published_misses")
	unpublishedDNSHits   = expvar.NewInt("counter_bootstrap_dns_unpublished_hits")
	unpublishedDNSMisses = expvar.NewInt("counter_bootstrap_dns_unpublished_misses")
)

func refreshBootstrapDNSLoop() {
	if *bootstrapDNS == "" && *unpublishedDNS == "" {
		return
	}
	for {
		refreshBootstrapDNS()
		refreshUnpublishedDNS()
		time.Sleep(10 * time.Minute)
	}
}

func refreshBootstrapDNS() {
	if *bootstrapDNS == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()
	dnsEntries := resolveList(ctx, strings.Split(*bootstrapDNS, ","))
	j, err := json.MarshalIndent(dnsEntries, "", "\t")
	if err != nil {
		// leave the old values in place
		return
	}

	dnsCache.Store(dnsEntries)
	dnsCacheBytes.Store(j)
}

func refreshUnpublishedDNS() {
	if *unpublishedDNS == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()

	dnsEntries := resolveList(ctx, strings.Split(*unpublishedDNS, ","))
	unpublishedDNSCache.Store(dnsEntries)
}

func resolveList(ctx context.Context, names []string) dnsEntryMap {
	dnsEntries := make(dnsEntryMap)

	var r net.Resolver
	for _, name := range names {
		addrs, err := r.LookupIP(ctx, "ip", name)
		if err != nil {
			log.Printf("bootstrap DNS lookup %q: %v", name, err)
			continue
		}
		dnsEntries[name] = addrs
	}
	return dnsEntries
}

func handleBootstrapDNS(w http.ResponseWriter, r *http.Request) {
	bootstrapDNSRequests.Add(1)

	w.Header().Set("Content-Type", "application/json")
	// Bootstrap DNS requests occur cross-regions, and are randomized per
	// request, so keeping a connection open is pointlessly expensive.
	w.Header().Set("Connection", "close")

	// Try answering a query from our hidden map first
	if q := r.URL.Query().Get("q"); q != "" {
		if ips, ok := unpublishedDNSCache.Load()[q]; ok && len(ips) > 0 {
			unpublishedDNSHits.Add(1)

			// Only return the specific query, not everything.
			m := dnsEntryMap{q: ips}
			j, err := json.MarshalIndent(m, "", "\t")
			if err == nil {
				w.Write(j)
				return
			}
		}

		// If we have a "q" query for a name in the published cache
		// list, then track whether that's a hit/miss.
		if m, ok := dnsCache.Load()[q]; ok {
			if len(m) > 0 {
				publishedDNSHits.Add(1)
			} else {
				publishedDNSMisses.Add(1)
			}
		} else {
			// If it wasn't in either cache, treat this as a query
			// for the unpublished cache, and thus a cache miss.
			unpublishedDNSMisses.Add(1)
		}
	}

	// Fall back to returning the public set of cached DNS names
	j := dnsCacheBytes.Load()
	w.Write(j)
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"expvar"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"tailscale.com/syncs"
	"tailscale.com/util/mak"
	"tailscale.com/util/slicesx"
)

const refreshTimeout = time.Minute

type dnsEntryMap struct {
	IPs     map[string][]net.IP
	Percent map[string]float64 // "foo.com" => 0.5 for 50%
}

var (
	dnsCache            atomic.Pointer[dnsEntryMap]
	dnsCacheBytes       syncs.AtomicValue[[]byte] // of JSON
	unpublishedDNSCache atomic.Pointer[dnsEntryMap]
	bootstrapLookupMap  syncs.Map[string, bool]
)

var (
	bootstrapDNSRequests        = expvar.NewInt("counter_bootstrap_dns_requests")
	publishedDNSHits            = expvar.NewInt("counter_bootstrap_dns_published_hits")
	publishedDNSMisses          = expvar.NewInt("counter_bootstrap_dns_published_misses")
	unpublishedDNSHits          = expvar.NewInt("counter_bootstrap_dns_unpublished_hits")
	unpublishedDNSMisses        = expvar.NewInt("counter_bootstrap_dns_unpublished_misses")
	unpublishedDNSPercentMisses = expvar.NewInt("counter_bootstrap_dns_unpublished_percent_misses")
)

func init() {
	expvar.Publish("counter_bootstrap_dns_queried_domains", expvar.Func(func() any {
		return bootstrapLookupMap.Len()
	}))
}

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
	dnsEntries := resolveList(ctx, *bootstrapDNS)
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

func refreshUnpublishedDNS() {
	if *unpublishedDNS == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()
	dnsEntries := resolveList(ctx, *unpublishedDNS)
	unpublishedDNSCache.Store(dnsEntries)
}

// resolveList takes a comma-separated list of DNS names to resolve.
//
// If an entry contains a slash, it's two DNS names: the first is the one to
// resolve and the second is that of a TXT recording containing the rollout
// percentage in range "0".."100". If the TXT record doesn't exist or is
// malformed, the percentage is 0. If the TXT record is not provided (there's no
// slash), then the percentage is 100.
func resolveList(ctx context.Context, list string) *dnsEntryMap {
	ents := strings.Split(list, ",")

	ret := &dnsEntryMap{}

	var r net.Resolver
	for _, ent := range ents {
		name, txtName, _ := strings.Cut(ent, "/")
		addrs, err := r.LookupIP(ctx, "ip", name)
		if err != nil {
			log.Printf("bootstrap DNS lookup %q: %v", name, err)
			continue
		}
		mak.Set(&ret.IPs, name, addrs)

		if txtName == "" {
			mak.Set(&ret.Percent, name, 1.0)
			continue
		}
		vals, err := r.LookupTXT(ctx, txtName)
		if err != nil {
			log.Printf("bootstrap DNS lookup %q: %v", txtName, err)
			continue
		}
		for _, v := range vals {
			if v, err := strconv.Atoi(v); err == nil && v >= 0 && v <= 100 {
				mak.Set(&ret.Percent, name, float64(v)/100)
			}
		}
	}
	return ret
}

func handleBootstrapDNS(w http.ResponseWriter, r *http.Request) {
	bootstrapDNSRequests.Add(1)

	w.Header().Set("Content-Type", "application/json")
	// Bootstrap DNS requests occur cross-regions, and are randomized per
	// request, so keeping a connection open is pointlessly expensive.
	w.Header().Set("Connection", "close")

	// Try answering a query from our hidden map first
	if q := r.URL.Query().Get("q"); q != "" {
		bootstrapLookupMap.Store(q, true)
		if bootstrapLookupMap.Len() > 500 { // defensive
			bootstrapLookupMap.Clear()
		}
		if m := unpublishedDNSCache.Load(); m != nil && len(m.IPs[q]) > 0 {
			unpublishedDNSHits.Add(1)

			percent := m.Percent[q]
			if remoteAddrMatchesPercent(r.RemoteAddr, percent) {
				// Only return the specific query, not everything.
				m := map[string][]net.IP{q: m.IPs[q]}
				j, err := json.MarshalIndent(m, "", "\t")
				if err == nil {
					w.Write(j)
					return
				}
			} else {
				unpublishedDNSPercentMisses.Add(1)
			}
		}

		// If we have a "q" query for a name in the published cache
		// list, then track whether that's a hit/miss.
		m := dnsCache.Load()
		var inPub bool
		var ips []net.IP
		if m != nil {
			ips, inPub = m.IPs[q]
		}
		if inPub {
			if len(ips) > 0 {
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

// percent is [0.0, 1.0].
func remoteAddrMatchesPercent(remoteAddr string, percent float64) bool {
	if percent == 0 {
		return false
	}
	if percent == 1 {
		return true
	}
	reqIPStr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	reqIP, err := netip.ParseAddr(reqIPStr)
	if err != nil {
		return false
	}
	if reqIP.IsLoopback() {
		// For local testing.
		return rand.Float64() < 0.5
	}
	reqIP16 := reqIP.As16()
	rndSrc := rand.NewPCG(binary.LittleEndian.Uint64(reqIP16[:8]), binary.LittleEndian.Uint64(reqIP16[8:]))
	rnd := rand.New(rndSrc)
	return percent > rnd.Float64()
}

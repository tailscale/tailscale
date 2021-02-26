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
	"sync"
	"time"
)

var (
	dnsMu    sync.Mutex
	dnsCache = map[string][]net.IP{}
)

var bootstrapDNSRequests = expvar.NewInt("counter_bootstrap_dns_requests")

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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	names := strings.Split(*bootstrapDNS, ",")
	var r net.Resolver
	for _, name := range names {
		addrs, err := r.LookupIP(ctx, "ip", name)
		if err != nil {
			log.Printf("bootstrap DNS lookup %q: %v", name, err)
			continue
		}
		dnsMu.Lock()
		dnsCache[name] = addrs
		dnsMu.Unlock()
	}
}

func handleBootstrapDNS(w http.ResponseWriter, r *http.Request) {
	bootstrapDNSRequests.Add(1)
	dnsMu.Lock()
	j, err := json.MarshalIndent(dnsCache, "", "\t")
	dnsMu.Unlock()
	if err != nil {
		log.Printf("bootstrap DNS JSON: %v", err)
		http.Error(w, "JSON marshal error", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

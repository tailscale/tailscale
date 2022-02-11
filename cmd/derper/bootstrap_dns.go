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
	"sync/atomic"
	"time"
)

var dnsCache atomic.Value // of []byte

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
	dnsEntries := make(map[string][]net.IP)
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
		dnsEntries[name] = addrs
	}
	j, err := json.MarshalIndent(dnsCache, "", "\t")
	if err != nil {
		// leave the old values in place
		return
	}
	dnsCache.Store(j)
}

func handleBootstrapDNS(w http.ResponseWriter, r *http.Request) {
	bootstrapDNSRequests.Add(1)
	j, _ := dnsCache.Load().([]byte)
	w.Write(j)
}

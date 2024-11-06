// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"tailscale.com/client/tailscale"
)

// healthz is a simple health check server, if enabled it returns 200 OK if
// this tailscale node currently has at least one tailnet IP address else
// returns 503.
type healthz struct {
	sync.Mutex
	hasAddrs bool
}

func (h *healthz) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Lock()
	defer h.Unlock()
	if h.hasAddrs {
		w.Write([]byte("ok"))
	} else {
		http.Error(w, "node currently has no tailscale IPs", http.StatusInternalServerError)
	}
}

// runHealthz runs a simple HTTP health endpoint on /healthz, listening on the
// provided address. A containerized tailscale instance is considered healthy if
// it has at least one tailnet IP address.
func run(addr string, h *healthz, lc *tailscale.LocalClient) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("error listening on the provided health endpoint address %q: %v", addr, err)
	}
	mux := http.NewServeMux()
	mux.Handle("/healthz", h)
	t := terminator{lc: lc}
	// /terminate is an endpoint that can be called from a prestop hook of this containerboot instance.
	// https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/#container-hooks It drops all
	// connections to and from Tailscale control plane. This can be used for containerboot instances that are HA
	// subnet routers. Control plane will consider the instance that is not responding as 'inactive' and prompt
	// peers to switch to another subnet router. Whilst this happens the existing connections will remain functional.
	mux.Handle("/terminate", t)
	hs := &http.Server{Handler: mux}

	go func() {
		if err := hs.Serve(lis); err != nil {
			log.Fatalf("failed running health endpoint: %v", err)
		}
	}()
}

type terminator struct {
	// nfr linuxfw.NetfilterRunner
	lc *tailscale.LocalClient
}

func (t terminator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("prestopBlockNetmapUpdates triggered")
	if err := t.lc.LameDuck(context.Background()); err != nil {
		log.Fatalf("error enabling lameduck: %v", err)
	}
	// tailscaleIPs, err := resolveDNS(context.Background(), "controlplane.tailscale.com")
	// if err != nil {
	// 	log.Printf("prestopBlockNetmapUpdates errored: %v", err)
	// 	return
	// }
	// var (
	// 	addrs []netip.Addr
	// )
	// for _, ip := range tailscaleIPs {
	// 	if ip.To4() != nil {
	// 		addrs = append(addrs, netip.AddrFrom4([4]byte(ip.To4())))
	// 	}
	// 	// just v4 for this prototype
	// }
	// for _, addr := range addrs {
	// 	log.Printf("dropping traffic to %v", addr)
	// 	if err := t.nfr.AddDropRule(addr); err != nil {
	// 		log.Printf("error adding drop rule for %v: %v", addr, err)
	// 	}
	// }
	log.Printf("sleeping to give control plane a chance to update...")
	time.Sleep(time.Second * 100)
	log.Printf("finished sleeping")
}

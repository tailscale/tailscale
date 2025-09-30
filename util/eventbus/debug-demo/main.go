// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// debug-demo is a program that serves a bus's debug interface over
// HTTP, then generates some fake traffic from a handful of
// clients. It is an aid to development, to have something to present
// on the debug interfaces while writing them.
package main

import (
	"log"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/tsweb"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus"
)

func main() {
	if !buildfeatures.HasDebugEventBus {
		log.Fatalf("debug-demo requires the \"debugeventbus\" feature enabled")
	}
	b := eventbus.New()
	c := b.Client("RouteMonitor")
	go testPub[RouteAdded](c, 5*time.Second)
	go testPub[RouteRemoved](c, 5*time.Second)
	c = b.Client("ControlClient")
	go testPub[PeerAdded](c, 3*time.Second)
	go testPub[PeerRemoved](c, 6*time.Second)
	c = b.Client("Portmapper")
	go testPub[PortmapAcquired](c, 10*time.Second)
	go testPub[PortmapLost](c, 15*time.Second)
	go testSub[RouteAdded](c)
	c = b.Client("WireguardConfig")
	go testSub[PeerAdded](c)
	go testSub[PeerRemoved](c)
	c = b.Client("Magicsock")
	go testPub[PeerPathChanged](c, 5*time.Second)
	go testSub[RouteAdded](c)
	go testSub[RouteRemoved](c)
	go testSub[PortmapAcquired](c)
	go testSub[PortmapLost](c)

	m := http.NewServeMux()
	d := tsweb.Debugger(m)
	b.Debugger().RegisterHTTP(d)

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/debug/bus", http.StatusFound)
	})
	log.Printf("Serving debug interface at http://localhost:8185/debug/bus")
	http.ListenAndServe(":8185", m)
}

func testPub[T any](c *eventbus.Client, every time.Duration) {
	p := eventbus.Publish[T](c)
	for {
		jitter := time.Duration(rand.N(2000)) * time.Millisecond
		time.Sleep(jitter)
		var zero T
		log.Printf("%s publish: %T", c.Name(), zero)
		p.Publish(zero)
		time.Sleep(every)
	}
}

func testSub[T any](c *eventbus.Client) {
	s := eventbus.Subscribe[T](c)
	for v := range s.Events() {
		log.Printf("%s received: %T", c.Name(), v)
	}
}

type RouteAdded struct {
	Prefix   netip.Prefix
	Via      netip.Addr
	Priority int
}
type RouteRemoved struct {
	Prefix netip.Addr
}

type PeerAdded struct {
	ID  int
	Key key.NodePublic
}
type PeerRemoved struct {
	ID  int
	Key key.NodePublic
}

type PortmapAcquired struct {
	Endpoint netip.Addr
}
type PortmapLost struct {
	Endpoint netip.Addr
}

type PeerPathChanged struct {
	ID         int
	EndpointID int
	Quality    int
}

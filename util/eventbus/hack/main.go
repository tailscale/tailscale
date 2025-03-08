package main

import (
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"time"

	"tailscale.com/tsweb"
	"tailscale.com/util/eventbus"
)

func main() {
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
		io.WriteString(w, "hi, I'm a demo eventbus server")
	})
	http.ListenAndServe(":8185", m)
}

func testPub[T any](c *eventbus.Client, every time.Duration) {
	p := eventbus.Publish[T](c)
	for {
		jitter := time.Duration(rand.N(2000)) * time.Millisecond
		time.Sleep(jitter)
		var zero T
		log.Printf("publish: %T", zero)
		p.Publish(zero)
		time.Sleep(every)
	}
}

func testSub[T any](c *eventbus.Client) {
	s := eventbus.Subscribe[T](c)
	for v := range s.Events() {
		log.Printf("received: %T", v)
	}
}

type RouteAdded struct{}
type RouteRemoved struct{}

type PeerAdded struct{}
type PeerRemoved struct{}

type PortmapAcquired struct{}
type PortmapLost struct{}

type PeerPathChanged struct{}

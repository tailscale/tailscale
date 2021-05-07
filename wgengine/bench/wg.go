// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/tailscale/wireguard-go/tun"
	"inet.af/netaddr"

	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/wgkey"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

func setupWGTest(b *testing.B, logf logger.Logf, traf *TrafficGen, a1, a2 netaddr.IPPrefix) {
	l1 := logger.WithPrefix(logf, "e1: ")
	k1, err := wgkey.NewPrivate()
	if err != nil {
		log.Fatalf("e1 NewPrivateKey: %v", err)
	}
	c1 := wgcfg.Config{
		Name:       "e1",
		PrivateKey: k1,
		Addresses:  []netaddr.IPPrefix{a1},
	}
	t1 := &sourceTun{
		logf: logger.WithPrefix(logf, "tun1: "),
		traf: traf,
	}
	e1, err := wgengine.NewUserspaceEngine(l1, wgengine.Config{
		Router:      router.NewFake(l1),
		LinkMonitor: nil,
		ListenPort:  0,
		Tun:         t1,
	})
	if err != nil {
		log.Fatalf("e1 init: %v", err)
	}
	if b != nil {
		b.Cleanup(e1.Close)
	}

	l2 := logger.WithPrefix(logf, "e2: ")
	k2, err := wgkey.NewPrivate()
	if err != nil {
		log.Fatalf("e2 NewPrivateKey: %v", err)
	}
	c2 := wgcfg.Config{
		Name:       "e2",
		PrivateKey: k2,
		Addresses:  []netaddr.IPPrefix{a2},
	}
	t2 := &sinkTun{
		logf: logger.WithPrefix(logf, "tun2: "),
		traf: traf,
	}
	e2, err := wgengine.NewUserspaceEngine(l2, wgengine.Config{
		Router:      router.NewFake(l2),
		LinkMonitor: nil,
		ListenPort:  0,
		Tun:         t2,
	})
	if err != nil {
		log.Fatalf("e2 init: %v", err)
	}
	if b != nil {
		b.Cleanup(e2.Close)
	}

	e1.SetFilter(filter.NewAllowAllForTest(l1))
	e2.SetFilter(filter.NewAllowAllForTest(l2))

	var wait sync.WaitGroup
	wait.Add(2)

	e1.SetStatusCallback(func(st *wgengine.Status, err error) {
		if err != nil {
			log.Fatalf("e1 status err: %v", err)
		}
		logf("e1 status: %v", *st)

		var eps []string
		for _, ep := range st.LocalAddrs {
			eps = append(eps, ep.Addr.String())
		}

		n := tailcfg.Node{
			ID:         tailcfg.NodeID(0),
			Name:       "n1",
			Addresses:  []netaddr.IPPrefix{a1},
			AllowedIPs: []netaddr.IPPrefix{a1},
			Endpoints:  eps,
		}
		e2.SetNetworkMap(&netmap.NetworkMap{
			NodeKey:    tailcfg.NodeKey(k2),
			PrivateKey: wgkey.Private(k2),
			Peers:      []*tailcfg.Node{&n},
		})

		p := wgcfg.Peer{
			PublicKey:  c1.PrivateKey.Public(),
			AllowedIPs: []netaddr.IPPrefix{a1},
			Endpoints:  strings.Join(eps, ","),
		}
		c2.Peers = []wgcfg.Peer{p}
		e2.Reconfig(&c2, &router.Config{}, new(dns.Config))
		wait.Done()
	})

	e2.SetStatusCallback(func(st *wgengine.Status, err error) {
		if err != nil {
			log.Fatalf("e2 status err: %v", err)
		}
		logf("e2 status: %v", *st)

		var eps []string
		for _, ep := range st.LocalAddrs {
			eps = append(eps, ep.Addr.String())
		}

		n := tailcfg.Node{
			ID:         tailcfg.NodeID(0),
			Name:       "n2",
			Addresses:  []netaddr.IPPrefix{a2},
			AllowedIPs: []netaddr.IPPrefix{a2},
			Endpoints:  eps,
		}
		e1.SetNetworkMap(&netmap.NetworkMap{
			NodeKey:    tailcfg.NodeKey(k1),
			PrivateKey: wgkey.Private(k1),
			Peers:      []*tailcfg.Node{&n},
		})

		p := wgcfg.Peer{
			PublicKey:  c2.PrivateKey.Public(),
			AllowedIPs: []netaddr.IPPrefix{a2},
			Endpoints:  strings.Join(eps, ","),
		}
		c1.Peers = []wgcfg.Peer{p}
		e1.Reconfig(&c1, &router.Config{}, new(dns.Config))
		wait.Done()
	})

	// Not using DERP in this test (for now?).
	e1.SetDERPMap(&tailcfg.DERPMap{})
	e2.SetDERPMap(&tailcfg.DERPMap{})

	wait.Wait()
}

type sourceTun struct {
	logf logger.Logf
	traf *TrafficGen
}

func (t *sourceTun) Close() error           { return nil }
func (t *sourceTun) Events() chan tun.Event { return nil }
func (t *sourceTun) File() *os.File         { return nil }
func (t *sourceTun) Flush() error           { return nil }
func (t *sourceTun) MTU() (int, error)      { return 1500, nil }
func (t *sourceTun) Name() (string, error)  { return "source", nil }

func (t *sourceTun) Write(b []byte, ofs int) (int, error) {
	// Discard all writes
	return len(b) - ofs, nil
}

func (t *sourceTun) Read(b []byte, ofs int) (int, error) {
	// Continually generate "input" packets
	n := t.traf.Generate(b, ofs)
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

type sinkTun struct {
	logf logger.Logf
	traf *TrafficGen
}

func (t *sinkTun) Close() error           { return nil }
func (t *sinkTun) Events() chan tun.Event { return nil }
func (t *sinkTun) File() *os.File         { return nil }
func (t *sinkTun) Flush() error           { return nil }
func (t *sinkTun) MTU() (int, error)      { return 1500, nil }
func (t *sinkTun) Name() (string, error)  { return "sink", nil }

func (t *sinkTun) Read(b []byte, ofs int) (int, error) {
	// Never returns
	select {}
}

func (t *sinkTun) Write(b []byte, ofs int) (int, error) {
	// Count packets, but discard them
	t.traf.GotPacket(b, ofs)
	return len(b) - ofs, nil
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"io"
	"log"
	"net/netip"
	"os"
	"sync"
	"testing"

	"github.com/tailscale/wireguard-go/tun"

	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

func epFromTyped(eps []tailcfg.Endpoint) (ret []netip.AddrPort) {
	for _, ep := range eps {
		ret = append(ret, ep.Addr)
	}
	return
}

func setupWGTest(b *testing.B, logf logger.Logf, traf *TrafficGen, a1, a2 netip.Prefix) {
	l1 := logger.WithPrefix(logf, "e1: ")
	k1 := key.NewNode()

	c1 := wgcfg.Config{
		PrivateKey: k1,
		Addresses:  []netip.Prefix{a1},
	}
	t1 := &sourceTun{
		logf: logger.WithPrefix(logf, "tun1: "),
		traf: traf,
	}
	s1 := tsd.NewSystem()
	e1, err := wgengine.NewUserspaceEngine(l1, wgengine.Config{
		Router:        router.NewFake(l1),
		NetMon:        nil,
		ListenPort:    0,
		Tun:           t1,
		SetSubsystem:  s1.Set,
		HealthTracker: s1.HealthTracker.Get(),
	})
	if err != nil {
		log.Fatalf("e1 init: %v", err)
	}
	if b != nil {
		b.Cleanup(e1.Close)
	}

	l2 := logger.WithPrefix(logf, "e2: ")
	k2 := key.NewNode()
	c2 := wgcfg.Config{
		PrivateKey: k2,
		Addresses:  []netip.Prefix{a2},
	}
	t2 := &sinkTun{
		logf: logger.WithPrefix(logf, "tun2: "),
		traf: traf,
	}
	s2 := tsd.NewSystem()
	e2, err := wgengine.NewUserspaceEngine(l2, wgengine.Config{
		Router:        router.NewFake(l2),
		NetMon:        nil,
		ListenPort:    0,
		Tun:           t2,
		SetSubsystem:  s2.Set,
		HealthTracker: s2.HealthTracker.Get(),
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

	var e1waitDoneOnce sync.Once
	e1.SetStatusCallback(func(st *wgengine.Status, err error) {
		if errors.Is(err, wgengine.ErrEngineClosing) {
			return
		}
		if err != nil {
			log.Fatalf("e1 status err: %v", err)
		}
		logf("e1 status: %v", *st)

		n := &tailcfg.Node{
			ID:         tailcfg.NodeID(0),
			Name:       "n1",
			Addresses:  []netip.Prefix{a1},
			AllowedIPs: []netip.Prefix{a1},
			Endpoints:  epFromTyped(st.LocalAddrs),
		}
		e2.SetNetworkMap(&netmap.NetworkMap{
			NodeKey: k2.Public(),
			Peers:   []tailcfg.NodeView{n.View()},
		})

		p := wgcfg.Peer{
			PublicKey:  c1.PrivateKey.Public(),
			AllowedIPs: []netip.Prefix{a1},
		}
		c2.Peers = []wgcfg.Peer{p}
		e2.Reconfig(&c2, &router.Config{}, new(dns.Config))
		e1waitDoneOnce.Do(wait.Done)
	})

	var e2waitDoneOnce sync.Once
	e2.SetStatusCallback(func(st *wgengine.Status, err error) {
		if errors.Is(err, wgengine.ErrEngineClosing) {
			return
		}
		if err != nil {
			log.Fatalf("e2 status err: %v", err)
		}
		logf("e2 status: %v", *st)

		n := &tailcfg.Node{
			ID:         tailcfg.NodeID(0),
			Name:       "n2",
			Addresses:  []netip.Prefix{a2},
			AllowedIPs: []netip.Prefix{a2},
			Endpoints:  epFromTyped(st.LocalAddrs),
		}
		e1.SetNetworkMap(&netmap.NetworkMap{
			NodeKey: k1.Public(),
			Peers:   []tailcfg.NodeView{n.View()},
		})

		p := wgcfg.Peer{
			PublicKey:  c2.PrivateKey.Public(),
			AllowedIPs: []netip.Prefix{a2},
		}
		c1.Peers = []wgcfg.Peer{p}
		e1.Reconfig(&c1, &router.Config{}, new(dns.Config))
		e2waitDoneOnce.Do(wait.Done)
	})

	// Not using DERP in this test (for now?).
	s1.MagicSock.Get().SetDERPMap(&tailcfg.DERPMap{})
	s2.MagicSock.Get().SetDERPMap(&tailcfg.DERPMap{})

	wait.Wait()
}

type sourceTun struct {
	logf logger.Logf
	traf *TrafficGen
}

func (t *sourceTun) Close() error             { return nil }
func (t *sourceTun) Events() <-chan tun.Event { return nil }
func (t *sourceTun) File() *os.File           { return nil }
func (t *sourceTun) Flush() error             { return nil }
func (t *sourceTun) MTU() (int, error)        { return 1500, nil }
func (t *sourceTun) Name() (string, error)    { return "source", nil }

// TODO(raggi): could be optimized for linux style batch sizes
func (t *sourceTun) BatchSize() int { return 1 }

func (t *sourceTun) Write(b [][]byte, ofs int) (int, error) {
	// Discard all writes
	return len(b), nil
}

func (t *sourceTun) Read(b [][]byte, sizes []int, ofs int) (int, error) {
	for i, b := range b {
		// Continually generate "input" packets
		n := t.traf.Generate(b, ofs)
		sizes[i] = n
		if n == 0 {
			return 0, io.EOF
		}
	}
	return len(b), nil
}

type sinkTun struct {
	logf logger.Logf
	traf *TrafficGen
}

func (t *sinkTun) Close() error             { return nil }
func (t *sinkTun) Events() <-chan tun.Event { return nil }
func (t *sinkTun) File() *os.File           { return nil }
func (t *sinkTun) Flush() error             { return nil }
func (t *sinkTun) MTU() (int, error)        { return 1500, nil }
func (t *sinkTun) Name() (string, error)    { return "sink", nil }

func (t *sinkTun) Read(b [][]byte, sizes []int, ofs int) (int, error) {
	// Never returns
	select {}
}

func (t *sinkTun) Write(b [][]byte, ofs int) (int, error) {
	// Count packets, but discard them
	for _, b := range b {
		t.traf.GotPacket(b, ofs)
	}
	return len(b), nil
}

// TODO(raggi): could be optimized for linux style batch sizes
func (t *sinkTun) BatchSize() int { return 1 }

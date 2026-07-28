// Copyright (c) Tailscale Inc & contributors
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
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

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

	// There is no LocalBackend in this benchmark, so install trivial
	// outbound peer lookups and per-peer config sources; without them,
	// outbound packets can't lazily create their WireGuard peer.
	k1pub, k2pub := k1.Public(), k2.Public()
	e1.SetPeerByIPPacketFunc(func(dst netip.Addr) (_ key.NodePublic, ok bool) {
		return k2pub, a2.Contains(dst)
	})
	e2.SetPeerByIPPacketFunc(func(dst netip.Addr) (_ key.NodePublic, ok bool) {
		return k1pub, a1.Contains(dst)
	})
	e1.SetPeerConfigFunc(func(pubk key.NodePublic) (_ []netip.Prefix, ok bool) {
		if pubk == k2pub {
			return []netip.Prefix{a2}, true
		}
		return nil, false
	})
	e2.SetPeerConfigFunc(func(pubk key.NodePublic) (_ []netip.Prefix, ok bool) {
		if pubk == k1pub {
			return []netip.Prefix{a1}, true
		}
		return nil, false
	})

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

		e2.SetSelfNode(tailcfg.NodeView{})
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

		e1.SetSelfNode(tailcfg.NodeView{})
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

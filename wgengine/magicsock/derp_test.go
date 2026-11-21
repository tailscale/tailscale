// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/health"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
)

func CheckDERPHeuristicTimes(t *testing.T) {
	if netcheck.PreferredDERPFrameTime <= frameReceiveRecordRate {
		t.Errorf("PreferredDERPFrameTime too low; should be at least frameReceiveRecordRate")
	}
}

func TestForceSetNearestDERP(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			7: {
				RegionID:   7,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "7a",
						RegionID: 7,
						HostName: "derp7.test.unused",
						IPv4:     "127.0.0.1",
						IPv6:     "none",
					},
				},
			},
		},
	}

	// Force the real control health check so we can verify force=true bypasses it.
	tstest.Replace(t, &checkControlHealthDuringNearestDERPInTests, true)

	bus := eventbustest.NewBus(t)
	ht := health.NewTracker(bus)
	c := newConn(t.Logf)
	ec := bus.Client("magicsock.Conn.Test")
	c.eventClient = ec
	c.homeDERPChangedPub = eventbus.Publish[HomeDERPChanged](ec)
	c.eventBus = bus
	c.derpMap = derpMap
	c.health = ht

	ht.SetOutOfPollNetMap()

	tw := eventbustest.NewWatcher(t, bus)

	got := c.ForceSetNearestDERP(7)
	if got != 7 {
		t.Fatalf("ForceSetNearestDERP(7) = %d, want 7", got)
	}
	if c.myDerp != 7 {
		t.Errorf("c.myDerp = %d after ForceSetNearestDERP, want 7", c.myDerp)
	}

	if err := eventbustest.Expect(tw, func(e HomeDERPChanged) error {
		if e.Old != 0 || e.New != 7 {
			return fmt.Errorf("got HomeDERPChanged{Old:%d, New:%d}, want {Old:0, New:7}", e.Old, e.New)
		}
		return nil
	}); err != nil {
		t.Errorf("expected HomeDERPChanged event: %v", err)
	}
}

func TestSetDERPMapDoReStun(t *testing.T) {
	derpMap1 := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "cph",
				Nodes: []*tailcfg.DERPNode{
					{Name: "1a", RegionID: 1, HostName: "cph.test.unused", IPv4: "127.0.0.1", IPv6: "none"},
				},
			},
		},
	}
	derpMap2 := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			2: {
				RegionID:   2,
				RegionCode: "inc",
				Nodes: []*tailcfg.DERPNode{
					{Name: "2a", RegionID: 2, HostName: "inc.test.unused", IPv4: "127.0.0.1", IPv6: "none"},
				},
			},
		},
	}

	var reSTUNCalls int
	tstest.Replace(t, &reSTUNHookForTests, func(_ string) {
		reSTUNCalls++
	})

	bus := eventbustest.NewBus(t)
	ht := health.NewTracker(bus)
	// Use WhileTestRunningLogger so the goroutine spawned by setDERPMap
	// (which calls ReSTUN, which logs) doesn't race with test cleanup.
	c := newConn(tstest.WhileTestRunningLogger(t))
	ec := bus.Client("magicsock.Conn.Test")
	c.eventClient = ec
	c.homeDERPChangedPub = eventbus.Publish[HomeDERPChanged](ec)
	c.eventBus = bus
	c.health = ht
	// With a zero private key and everHadKey=true, ReSTUN returns early without
	// spawning updateEndpoints.
	c.everHadKey = true

	// SetDERPMapWithoutReSTUN should not trigger a ReSTUN.
	c.SetDERPMapWithoutReSTUN(derpMap1)
	if reSTUNCalls != 0 {
		t.Errorf("SetDERPMapWithoutReSTUN: got %d ReSTUN calls, want 0", reSTUNCalls)
	}

	// SetDERPMap should trigger a ReSTUN.
	c.SetDERPMap(derpMap2)
	if reSTUNCalls != 1 {
		t.Errorf("SetDERPMap: got %d ReSTUN calls, want 1", reSTUNCalls)
	}
}

// freezableProxy is a TCP proxy whose connections can be frozen: a
// frozen connection stays open but silently drops everything in both
// directions, like a TCP connection whose NAT mapping expired while
// the device was asleep.
type freezableProxy struct {
	ln     net.Listener
	target string

	mu     sync.Mutex
	frozen map[netip.AddrPort]*atomic.Bool // by client address
}

func newFreezableProxy(t *testing.T, target string) *freezableProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &freezableProxy{ln: ln, target: target, frozen: map[netip.AddrPort]*atomic.Bool{}}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.proxy(c)
		}
	}()
	return p
}

func (p *freezableProxy) port() int { return p.ln.Addr().(*net.TCPAddr).Port }

func (p *freezableProxy) proxy(c net.Conn) {
	defer c.Close()
	up, err := net.Dial("tcp", p.target)
	if err != nil {
		return
	}
	defer up.Close()
	frozen := new(atomic.Bool)
	p.mu.Lock()
	p.frozen[c.RemoteAddr().(*net.TCPAddr).AddrPort()] = frozen
	p.mu.Unlock()

	copyUnlessFrozen := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			if frozen.Load() {
				continue
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
	}
	done := make(chan struct{}, 2)
	go func() { copyUnlessFrozen(up, c); done <- struct{}{} }()
	go func() { copyUnlessFrozen(c, up); done <- struct{}{} }()
	<-done
}

// freeze freezes the proxied connection from the client address src.
func (p *freezableProxy) freeze(t *testing.T, src netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, ok := p.frozen[src]
	if !ok {
		t.Fatalf("no proxied connection from %v", src)
	}
	f.Store(true)
}

// activeDERPLocalAddr returns the local address of conn's connection to
// DERP region 1, or an error if it isn't connected.
func activeDERPLocalAddr(conn *Conn) (netip.AddrPort, error) {
	conn.mu.Lock()
	ad, ok := conn.activeDerp[1]
	conn.mu.Unlock()
	if !ok {
		return netip.AddrPort{}, errors.New("no DERP connection")
	}
	return ad.c.LocalAddr()
}

// newQuietDERPTestConn returns a Conn whose home is DERP region 1, which
// it reaches through the returned proxy.
func newQuietDERPTestConn(t *testing.T) (*Conn, *freezableProxy) {
	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	t.Cleanup(cleanup)
	node := derpMap.Regions[1].Nodes[0]
	proxy := newFreezableProxy(t, net.JoinHostPort(node.IPv4, fmt.Sprint(node.DERPPort)))
	node.DERPPort = proxy.port()

	bus := eventbustest.NewBus(t)
	netMon, err := netmon.New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netMon.Close() })
	conn, err := NewConn(Options{
		Logf:                   tstest.WhileTestRunningLogger(t),
		NetMon:                 netMon,
		EventBus:               bus,
		HealthTracker:          health.NewTracker(bus),
		Metrics:                new(usermetric.Registry),
		DisablePortMapper:      true,
		TestOnlyPacketListener: localhostListener{},
		EndpointsFunc:          func([]tailcfg.Endpoint) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDERPMap(derpMap)
	if err := conn.SetPrivateKey(key.NewNode()); err != nil {
		t.Fatal(err)
	}
	conn.WaitReady(t)
	conn.ForceSetNearestDERP(1)
	return conn, proxy
}

// TestQuietDERPConnPingedBeforeWrite tests that writing to a DERP
// connection that has been silent for longer than the server keepalive
// interval pings the server first, and reconnects if the connection is
// dead, rather than writing into it until the read deadline expires.
//
// See https://github.com/tailscale/tailscale/issues/15776.
func TestQuietDERPConnPingedBeforeWrite(t *testing.T) {
	conn, proxy := newQuietDERPTestConn(t)

	activeDERP := func() (activeDerp, bool) {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		ad, ok := conn.activeDerp[1]
		return ad, ok
	}
	var first activeDerp
	if err := tstest.WaitFor(5*time.Second, func() error {
		var ok bool
		if first, ok = activeDERP(); !ok {
			return errors.New("no DERP connection yet")
		}
		return first.c.Ping(context.Background())
	}); err != nil {
		t.Fatal(err)
	}

	// A recently heard-from connection is written to without a ping.
	conn.derpWriteChanForRegion(1, key.NodePublic{})
	if first.recv.pinging.Load() {
		t.Fatal("pinged a DERP connection that was recently heard from")
	}

	// Simulate waking from sleep: the connection is dead, but nothing
	// has noticed, and the last frame was received long ago.
	la, err := first.c.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	proxy.freeze(t, la)
	first.recv.noteFrame(time.Now().Add(-2 * derpQuietPingThreshold))

	failsBefore := metricDERPQuietPingFail.Value()
	conn.derpWriteChanForRegion(1, key.NodePublic{})

	// The ping can't get through the frozen connection, so the
	// connection is closed well before the 2 minute read deadline, and
	// a working one replaces it.
	if err := tstest.WaitFor(10*time.Second, func() error {
		cur, ok := activeDERP()
		if !ok || cur.c == first.c {
			return errors.New("dead DERP connection not replaced yet")
		}
		return cur.c.Ping(context.Background())
	}); err != nil {
		t.Fatal(err)
	}
	if got := metricDERPQuietPingFail.Value() - failsBefore; got != 1 {
		t.Errorf("derp_quiet_ping_fail increased by %d, want 1", got)
	}
}

// TestQuietDERPConnPingSuccessKeepsConn tests that a quiet but live DERP
// connection is kept after its liveness ping succeeds.
func TestQuietDERPConnPingSuccessKeepsConn(t *testing.T) {
	conn, _ := newQuietDERPTestConn(t)

	var ad activeDerp
	if err := tstest.WaitFor(5*time.Second, func() error {
		conn.mu.Lock()
		var ok bool
		ad, ok = conn.activeDerp[1]
		conn.mu.Unlock()
		if !ok {
			return errors.New("no DERP connection yet")
		}
		return ad.c.Ping(context.Background())
	}); err != nil {
		t.Fatal(err)
	}
	la, err := ad.c.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}

	stale := time.Now().Add(-2 * derpQuietPingThreshold)
	ad.recv.noteFrame(stale)
	conn.derpWriteChanForRegion(1, key.NodePublic{})

	if err := tstest.WaitFor(5*time.Second, func() error {
		if ad.recv.pinging.Load() || ad.recv.lastFrame.Load() == stale.UnixNano() {
			return errors.New("liveness ping not done yet")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	conn.mu.Lock()
	cur := conn.activeDerp[1]
	conn.mu.Unlock()
	if cur.c != ad.c {
		t.Error("live DERP connection was replaced after a successful ping")
	}
	if got, err := activeDERPLocalAddr(conn); err != nil || got != la {
		t.Errorf("DERP connection local address = %v, %v; want %v (no reconnect)", got, err, la)
	}
}

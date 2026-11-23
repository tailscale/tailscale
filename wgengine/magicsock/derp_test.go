// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/derp/derpserver"
	// Registers the WebSocket fallback for DERP dials in this test binary,
	// which TestRebindKeepsWebSocketDERP needs.
	_ "tailscale.com/feature/derpwebsocket"
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

// TestRebindKeepsWebSocketDERP checks that a rebind doesn't close a DERP
// connection that came up over WebSocket. Such a connection can't report
// its local address, so it must get the post-rebind ping instead.
func TestRebindKeepsWebSocketDERP(t *testing.T) {
	// The DERP reader and server goroutines can still log while the
	// connections shut down, after the test has returned.
	base := tstest.WhileTestRunningLogger(t)
	pingResult := make(chan string, 1)
	logf := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		var res string
		switch {
		case strings.Contains(msg, "post-rebind ping of DERP region 1 okay"):
			res = "ok"
		case strings.Contains(msg, "rebind-ping-fail"):
			res = "failed"
		}
		if res != "" {
			select {
			case pingResult <- res:
			default:
			}
		}
		base(format, args...)
	}

	// Refuse "Upgrade: DERP" so the client falls back to WebSocket.
	derpMap, cleanup := runDERPAndStunWithHandler(t, logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1), func(d *derpserver.Server) http.Handler {
		derpOnly := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.EqualFold(r.Header.Get("Upgrade"), "derp") {
				http.Error(w, "DERP upgrade blocked", http.StatusForbidden)
				return
			}
			derpserver.Handler(d).ServeHTTP(w, r)
		})
		return derpserver.AddWebSocketSupport(d, derpOnly)
	})
	defer cleanup()

	bus := eventbustest.NewBus(t)
	netMon, err := netmon.New(bus, logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netMon.Close() })

	conn, err := NewConn(Options{
		Logf:                   logf,
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
	defer conn.Close()

	conn.SetDERPMap(derpMap)
	if err := conn.SetPrivateKey(key.NewNode()); err != nil {
		t.Fatal(err)
	}
	conn.WaitReady(t)

	var ad activeDerp
	if err := tstest.WaitFor(10*time.Second, func() error {
		conn.mu.Lock()
		ad = conn.activeDerp[1]
		conn.mu.Unlock()
		if ad.c == nil {
			return errors.New("no DERP connection")
		}
		la, err := ad.c.LocalAddr()
		if err != nil {
			return err
		}
		if la.IsValid() {
			return fmt.Errorf("LocalAddr = %v; want invalid, as for a WebSocket connection", la)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	conn.maybeCloseDERPsOnRebind([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})

	sameConn := func() bool {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		after, ok := conn.activeDerp[1]
		return ok && after.c == ad.c
	}
	if !sameConn() {
		t.Fatal("rebind closed the WebSocket DERP connection")
	}
	select {
	case res := <-pingResult:
		if res != "ok" {
			t.Fatalf("post-rebind ping %s", res)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no post-rebind ping result")
	}
	if !sameConn() {
		t.Fatal("WebSocket DERP connection was replaced after the post-rebind ping")
	}
}

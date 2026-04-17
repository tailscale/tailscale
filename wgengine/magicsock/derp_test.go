// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"fmt"
	"testing"

	"tailscale.com/health"
	"tailscale.com/net/netcheck"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
)

func CheckDERPHeuristicTimes(t *testing.T) {
	if netcheck.PreferredDERPFrameTime <= frameReceiveRecordRate {
		t.Errorf("PreferredDERPFrameTime too low; should be at least frameReceiveRecordRate")
	}
}

func TestForceSetNearestDERP(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
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
		Regions: map[int]*tailcfg.DERPRegion{
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
		Regions: map[int]*tailcfg.DERPRegion{
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
	c := newConn(t.Logf)
	ec := bus.Client("magicsock.Conn.Test")
	c.eventClient = ec
	c.homeDERPChangedPub = eventbus.Publish[HomeDERPChanged](ec)
	c.eventBus = bus
	c.health = ht
	// With a zero private key and everHadKey=true, ReSTUN returns early without
	// spawning updateEndpoints.
	c.everHadKey = true

	// Should not trigger a ReSTUN.
	c.SetDERPMap(derpMap1, false)
	if reSTUNCalls != 0 {
		t.Errorf("SetDERPMap(dm, doReStun=false): got %d ReSTUN calls, want 0", reSTUNCalls)
	}

	// doReStun=true: should trigger a ReSTUN.
	c.SetDERPMap(derpMap2, true)
	if reSTUNCalls != 1 {
		t.Errorf("SetDERPMap(dm, doReStun=true): got %d ReSTUN calls, want 1", reSTUNCalls)
	}
}

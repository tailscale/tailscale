// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netlog && !ts_omit_logtail

package netlog

import (
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/tailcfg"
	"tailscale.com/types/bools"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/netlogtype"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/router"
)

func TestEmbedNodeInfo(t *testing.T) {
	// Initialize the logger with a particular view of the netmap.
	var logger Logger
	logger.ReconfigNetworkMap(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			StableID:  "n123456CNTL",
			ID:        123456,
			Name:      "test.tail123456.ts.net",
			Addresses: []netip.Prefix{prefix("100.1.2.3")},
			Tags:      []string{"tag:foo", "tag:bar"},
		}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				StableID:  "n123457CNTL",
				ID:        123457,
				Name:      "peer1.tail123456.ts.net",
				Addresses: []netip.Prefix{prefix("100.1.2.4")},
				Tags:      []string{"tag:peer"},
			}).View(),
			(&tailcfg.Node{
				StableID:  "n123458CNTL",
				ID:        123458,
				Name:      "peer2.tail123456.ts.net",
				Addresses: []netip.Prefix{prefix("100.1.2.5")},
				User:      54321,
			}).View(),
		},
		UserProfiles: map[tailcfg.UserID]tailcfg.UserProfileView{
			54321: (&tailcfg.UserProfile{ID: 54321, LoginName: "peer@example.com"}).View(),
		},
	})
	logger.ReconfigRoutes(&router.Config{
		SubnetRoutes: []netip.Prefix{
			prefix("172.16.1.1/16"),
			prefix("192.168.1.1/24"),
		},
	})

	// Update the counters for a few connections.
	var group sync.WaitGroup
	defer group.Wait()
	conns := []struct {
		virt               bool
		proto              ipproto.Proto
		src, dst           netip.AddrPort
		txP, txB, rxP, rxB int
	}{
		{true, 0x6, addrPort("100.1.2.3:80"), addrPort("100.1.2.4:1812"), 88, 278, 34, 887},
		{true, 0x6, addrPort("100.1.2.3:443"), addrPort("100.1.2.5:1742"), 96, 635, 23, 790},
		{true, 0x6, addrPort("100.1.2.3:443"), addrPort("100.1.2.6:1175"), 48, 94, 86, 618}, // unknown peer (in Tailscale IP space, but not a known peer)
		{true, 0x6, addrPort("100.1.2.3:80"), addrPort("192.168.1.241:713"), 43, 154, 66, 883},
		{true, 0x6, addrPort("100.1.2.3:80"), addrPort("192.168.2.241:713"), 43, 154, 66, 883}, // not in the subnet, must be exit traffic
		{true, 0x6, addrPort("100.1.2.3:80"), addrPort("172.16.5.18:713"), 7, 243, 40, 59},
		{true, 0x6, addrPort("100.1.2.3:80"), addrPort("172.20.5.18:713"), 61, 753, 42, 492}, // not in the subnet, must be exit traffic
		{true, 0x6, addrPort("192.168.1.241:713"), addrPort("100.1.2.3:80"), 43, 154, 66, 883},
		{true, 0x6, addrPort("192.168.2.241:713"), addrPort("100.1.2.3:80"), 43, 154, 66, 883}, // not in the subnet, must be exit traffic
		{true, 0x6, addrPort("172.16.5.18:713"), addrPort("100.1.2.3:80"), 7, 243, 40, 59},
		{true, 0x6, addrPort("172.20.5.18:713"), addrPort("100.1.2.3:80"), 61, 753, 42, 492},              // not in the subnet, must be exit traffic
		{true, 0x6, addrPort("14.255.192.128:39230"), addrPort("243.42.106.193:48206"), 81, 791, 79, 316}, // unknown connection
		{false, 0x6, addrPort("100.1.2.4:0"), addrPort("35.92.180.165:9743"), 63, 136, 61, 409},           // physical traffic with peer1
		{false, 0x6, addrPort("100.1.2.5:0"), addrPort("131.19.35.17:9743"), 88, 452, 2, 716},             // physical traffic with peer2
	}
	for range 10 {
		for _, conn := range conns {
			update := bools.IfElse(conn.virt, logger.updateVirtConn, logger.updatePhysConn)
			group.Go(func() { update(conn.proto, conn.src, conn.dst, conn.txP, conn.txB, false) })
			group.Go(func() { update(conn.proto, conn.src, conn.dst, conn.rxP, conn.rxB, true) })
		}
	}
	group.Wait()

	// Verify that the counters match.
	got := logger.record.toMessage(false, false)
	got.Start = time.Time{} // avoid flakiness
	want := netlogtype.Message{
		NodeID: "n123456CNTL",
		SrcNode: netlogtype.Node{
			NodeID:    "n123456CNTL",
			Name:      "test.tail123456.ts.net",
			Addresses: []netip.Addr{addr("100.1.2.3")},
			Tags:      []string{"tag:bar", "tag:foo"},
		},
		DstNodes: []netlogtype.Node{{
			NodeID:    "n123457CNTL",
			Name:      "peer1.tail123456.ts.net",
			Addresses: []netip.Addr{addr("100.1.2.4")},
			Tags:      []string{"tag:peer"},
		}, {
			NodeID:    "n123458CNTL",
			Name:      "peer2.tail123456.ts.net",
			Addresses: []netip.Addr{addr("100.1.2.5")},
			User:      "peer@example.com",
		}},
		VirtualTraffic: []netlogtype.ConnectionCounts{
			{Connection: conn(0x6, "100.1.2.3:80", "100.1.2.4:1812"), Counts: counts(880, 2780, 340, 8870)},
			{Connection: conn(0x6, "100.1.2.3:443", "100.1.2.5:1742"), Counts: counts(960, 6350, 230, 7900)},
		},
		SubnetTraffic: []netlogtype.ConnectionCounts{
			{Connection: conn(0x6, "100.1.2.3:80", "172.16.5.18:713"), Counts: counts(70, 2430, 400, 590)},
			{Connection: conn(0x6, "100.1.2.3:80", "192.168.1.241:713"), Counts: counts(430, 1540, 660, 8830)},
			{Connection: conn(0x6, "172.16.5.18:713", "100.1.2.3:80"), Counts: counts(70, 2430, 400, 590)},
			{Connection: conn(0x6, "192.168.1.241:713", "100.1.2.3:80"), Counts: counts(430, 1540, 660, 8830)},
		},
		ExitTraffic: []netlogtype.ConnectionCounts{
			{Connection: conn(0x6, "14.255.192.128:39230", "243.42.106.193:48206"), Counts: counts(810, 7910, 790, 3160)},
			{Connection: conn(0x6, "100.1.2.3:80", "172.20.5.18:713"), Counts: counts(610, 7530, 420, 4920)},
			{Connection: conn(0x6, "100.1.2.3:80", "192.168.2.241:713"), Counts: counts(430, 1540, 660, 8830)},
			{Connection: conn(0x6, "100.1.2.3:443", "100.1.2.6:1175"), Counts: counts(480, 940, 860, 6180)},
			{Connection: conn(0x6, "172.20.5.18:713", "100.1.2.3:80"), Counts: counts(610, 7530, 420, 4920)},
			{Connection: conn(0x6, "192.168.2.241:713", "100.1.2.3:80"), Counts: counts(430, 1540, 660, 8830)},
		},
		PhysicalTraffic: []netlogtype.ConnectionCounts{
			{Connection: conn(0x6, "100.1.2.4:0", "35.92.180.165:9743"), Counts: counts(630, 1360, 610, 4090)},
			{Connection: conn(0x6, "100.1.2.5:0", "131.19.35.17:9743"), Counts: counts(880, 4520, 20, 7160)},
		},
	}
	if d := cmp.Diff(got, want, cmpopts.EquateComparable(netip.Addr{}, netip.AddrPort{})); d != "" {
		t.Errorf("Message (-got +want):\n%s", d)
	}
}

func TestUpdateRace(t *testing.T) {
	var logger Logger
	logger.recordsChan = make(chan record, 1)
	go func(recordsChan chan record) {
		for range recordsChan {
		}
	}(logger.recordsChan)

	var group sync.WaitGroup
	defer group.Wait()
	for i := range 1000 {
		group.Go(func() {
			src, dst := randAddrPort(), randAddrPort()
			for j := range 1000 {
				if i%2 == 0 {
					logger.updateVirtConn(0x1, src, dst, rand.IntN(10), rand.IntN(1000), j%2 == 0)
				} else {
					logger.updatePhysConn(0x1, src, dst, rand.IntN(10), rand.IntN(1000), j%2 == 0)
				}
			}
		})
		group.Go(func() {
			for range 1000 {
				logger.ReconfigNetworkMap(new(netmap.NetworkMap))
			}
		})
		group.Go(func() {
			for range 1000 {
				logger.ReconfigRoutes(new(router.Config))
			}
		})
	}

	group.Wait()
	logger.mu.Lock()
	close(logger.recordsChan)
	logger.recordsChan = nil
	logger.mu.Unlock()
}

func randAddrPort() netip.AddrPort {
	var b [4]uint8
	binary.LittleEndian.PutUint32(b[:], rand.Uint32())
	return netip.AddrPortFrom(netip.AddrFrom4(b), uint16(rand.Uint32()))
}

func TestAutoFlushMaxConns(t *testing.T) {
	var logger Logger
	logger.recordsChan = make(chan record, 1)
	for i := 0; len(logger.recordsChan) == 0; i++ {
		logger.updateVirtConn(0, netip.AddrPortFrom(netip.Addr{}, uint16(i)), netip.AddrPort{}, 1, 1, false)
	}
	b, _ := jsonv2.Marshal(logger.recordsChan)
	if len(b) > maxLogSize {
		t.Errorf("len(Message) = %v, want <= %d", len(b), maxLogSize)
	}
}

func TestAutoFlushTimeout(t *testing.T) {
	var logger Logger
	logger.recordsChan = make(chan record, 1)
	synctest.Test(t, func(t *testing.T) {
		logger.updateVirtConn(0, netip.AddrPort{}, netip.AddrPort{}, 1, 1, false)
		time.Sleep(pollPeriod)
	})
	rec := <-logger.recordsChan
	if d := rec.end.Sub(rec.start); d != pollPeriod {
		t.Errorf("window = %v, want %v", d, pollPeriod)
	}
	if len(rec.virtConns) != 1 {
		t.Errorf("len(virtConns) = %d, want 1", len(rec.virtConns))
	}
}

func BenchmarkUpdateSameConn(b *testing.B) {
	var logger Logger
	b.ReportAllocs()
	for range b.N {
		logger.updateVirtConn(0, netip.AddrPort{}, netip.AddrPort{}, 1, 1, false)
	}
}

func BenchmarkUpdateNewConns(b *testing.B) {
	var logger Logger
	b.ReportAllocs()
	for i := range b.N {
		logger.updateVirtConn(0, netip.AddrPortFrom(netip.Addr{}, uint16(i)), netip.AddrPort{}, 1, 1, false)
	}
}

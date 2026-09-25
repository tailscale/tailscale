// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"go4.org/netipx"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/tstest"
	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
)

func TestConnectorExpireTransitIPs(t *testing.T) {
	const appName = "app"

	peerA := netip.MustParseAddr("100.101.101.101")
	peerANode := (&tailcfg.Node{ID: 1, Addresses: []netip.Prefix{netip.PrefixFrom(peerA, 32)}}).View()

	peerB := netip.MustParseAddr("100.101.101.102")
	peerBNode := (&tailcfg.Node{ID: 2, Addresses: []netip.Prefix{netip.PrefixFrom(peerB, 32)}}).View()

	tipOne := netip.MustParseAddr("0.0.0.1")
	tipTwo := netip.MustParseAddr("0.0.0.2")
	tipThree := netip.MustParseAddr("0.0.0.3")
	tipFour := netip.MustParseAddr("0.0.0.4")

	c := newConn25(logger.Discard)
	c.reconfig(&config{
		isConfigured: true,
		appsByName:   map[string]appctype.Conn25Attr{appName: {}},
		ipSets:       ipSets{v4Transit: mustIPSetFromPrefix("0.0.0.0/15")},
	})
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Now()})
	// this would be a data race if we had started the sweeper, but we haven't.
	c.connector.clock = clock

	peerCap := tailcfg.PeerCapMap{
		peercap.Conn25Prefix.ToAttribute(appName): []tailcfg.RawMessage{`"*"`},
	}

	register := func(peer tailcfg.NodeView, tip, dst netip.Addr) {
		c.handleConnectorTransitIPRequest(peer, peerCap, ConnectorTransitIPRequest{
			TransitIPs: []TransitIPRequest{{TransitIP: tip, DestinationIP: dst, App: appName}},
		})
	}

	register(peerANode, tipOne, netip.MustParseAddr("10.0.0.1"))
	register(peerANode, tipFour, netip.MustParseAddr("10.0.0.4"))
	register(peerBNode, tipThree, netip.MustParseAddr("10.0.0.3"))

	clock.Advance(30 * time.Minute)
	register(peerANode, tipTwo, netip.MustParseAddr("10.0.0.2"))
	// write over the tipFour mapping, with a different dst
	register(peerANode, tipFour, netip.MustParseAddr("10.0.0.5"))

	// advance past the hour expiry time of peerA+tipOne and peerB+tipThree
	// the peerA+tipTwo and the updated peerA+tipFour registrations are still within expiry
	clock.Advance(31 * time.Minute)
	if got := c.connector.expireTransitIPs(clock.Now()); got != 2 {
		t.Fatalf("expireTransitIPs removed %d mappings, want 2", got)
	}

	c.connector.mu.Lock()
	if _, ok := c.connector.transitIPs[peerA][tipOne]; ok {
		t.Fatalf("expected tipOne %v to be removed from the map", tipOne)
	}
	if _, ok := c.connector.transitIPs[peerA][tipTwo]; !ok {
		t.Fatalf("expected tipTwo %v to remain in the map", tipTwo)
	}
	if _, ok := c.connector.transitIPs[peerB]; ok {
		t.Fatalf("expected peerB sub-map to be pruned after its only mapping expired")
	}
	c.connector.mu.Unlock()

	// advance another 30 mins, expire the other two mappings
	clock.Advance(30 * time.Minute)
	if got := c.connector.expireTransitIPs(clock.Now()); got != 2 {
		t.Fatalf("expireTransitIPs removed %d mappings, want 2", got)
	}
	c.connector.mu.Lock()
	if c.connector.expiryQueue.Len() != 0 {
		t.Fatalf("queue should be all done now")
	}
	if _, ok := c.connector.transitIPs[peerA]; ok {
		t.Fatalf("expected peerA sub-map to be pruned after all mappings expired")
	}
	c.connector.mu.Unlock()

	uint32ToIPv4 := func(n uint32) netip.Addr {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], n)
		return netip.AddrFrom4(buf)
	}
	var i uint32
	for i = 0; i < 100003; i++ {
		tip := uint32ToIPv4(i + 10)
		dst := uint32ToIPv4(i + 100014)
		register(peerANode, tip, dst)
	}
	// go past expiry time out
	clock.Advance(61 * time.Minute)
	if got := c.connector.expireTransitIPs(clock.Now()); got != 100000 {
		t.Fatalf("expireTransitIPs removed %d mappings, want 100000, the limit for one run", got)
	}
	c.connector.mu.Lock()
	if c.connector.expiryQueue.Len() != 3 {
		t.Fatalf("expected 3 items remaining in queue")
	}
	if len(c.connector.transitIPs[peerA]) != 3 {
		t.Fatalf("expected 3 items remaining in peerA transitIPs")
	}
	c.connector.mu.Unlock()
}

func TestConnectorPacketFilterAllow(t *testing.T) {
	src := netip.MustParseAddr("100.64.0.1")
	knownTip := netip.MustParseAddr("192.0.2.1")
	unknownTip := netip.MustParseAddr("100.64.0.42")

	v4TransitIPsBuilder := netipx.IPSetBuilder{}
	v4TransitIPsBuilder.AddPrefix(netip.MustParsePrefix("192.0.2.0/24"))
	v4TransitIPs := must.Get(v4TransitIPsBuilder.IPSet())

	c := newConn25(t.Logf)
	c.reconfig(&config{
		isConfigured: true,
		ipSets: ipSets{
			v4Transit: v4TransitIPs,
		},
	})

	if allow, _ := c.connector.packetFilterAllow(packet.Parsed{
		Src: netip.AddrPortFrom(src, 1234),
		Dst: netip.AddrPortFrom(knownTip, 1234),
	}); !allow {
		t.Fatal("knownTip: should have been allowed")
	}

	if allow, _ := c.connector.packetFilterAllow(packet.Parsed{
		Src: netip.AddrPortFrom(src, 1234),
		Dst: netip.AddrPortFrom(unknownTip, 1234),
	}); allow {
		t.Fatal("unknownTip: should not have been allowed")
	}
}

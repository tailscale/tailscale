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
		appsByName:   map[string]appctype.AppConnectorAttr{appName: {}},
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

	register(peerANode, tipOne, netip.MustParseAddr("203.0.113.1"))
	register(peerANode, tipFour, netip.MustParseAddr("203.0.113.4"))
	register(peerBNode, tipThree, netip.MustParseAddr("203.0.113.3"))

	clock.Advance(30 * time.Minute)
	register(peerANode, tipTwo, netip.MustParseAddr("203.0.113.2"))
	// write over the tipFour mapping, with a different dst
	register(peerANode, tipFour, netip.MustParseAddr("203.0.113.5"))

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
	// Transit IPs come from the pool configured above; destinations have to
	// stay out of it, or they'd be refused for being inside a configured pool.
	// The pool is 0.0.0.0/15, so the destinations start past 0.1.255.255.
	const dstBase = 200000 // 0.3.13.64
	var i uint32
	for i = 0; i < 100003; i++ {
		tip := uint32ToIPv4(i + 10)
		dst := uint32ToIPv4(i + dstBase)
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

// TestConnectorDisallowedDestinations checks which destinations
// [connector.handleTransitIPRequest] refuses: the ranges
// [routelimits.IsDisallowed] covers, private addresses, and the configured
// magic and transit IP pools. Addresses just outside those ranges have to
// still be accepted, so that the checks can't pass by refusing everything.
func TestConnectorDisallowedDestinations(t *testing.T) {
	const appName = "app"

	peerV4 := netip.MustParseAddr("100.101.101.101")
	peerV6 := netip.MustParseAddr("fd7a:115c:a1e0::101")
	peerNode := (&tailcfg.Node{ID: 1, Addresses: []netip.Prefix{
		netip.PrefixFrom(peerV4, 32),
		netip.PrefixFrom(peerV6, 128),
	}}).View()

	c := newConn25(logger.Discard)
	c.reconfig(&config{
		isConfigured: true,
		appsByName:   map[string]appctype.AppConnectorAttr{appName: {}},
		ipSets: ipSets{
			v4Magic:   mustIPSetFromPrefix("203.0.113.0/24"),
			v4Transit: mustIPSetFromPrefix("198.51.100.0/24"),
			v6Magic:   mustIPSetFromPrefix("2001:db8:11::/64"),
			v6Transit: mustIPSetFromPrefix("2001:db8:22::/64"),
		},
	})

	peerCap := tailcfg.PeerCapMap{
		peercap.Conn25Prefix.ToAttribute(appName): []tailcfg.RawMessage{`"*"`},
	}

	tests := []struct {
		name     string
		dst      string
		wantCode TransitIPResponseCode
	}{
		// Destinations that have to keep working. The 172 and ULA cases sit
		// just outside the private ranges, and 192.0.2.255 is a reminder that
		// a last octet of 255 is not in itself a broadcast address.
		{name: "globally-routable-v4", dst: "192.0.2.5", wantCode: OK},
		{name: "globally-routable-v6", dst: "2001:db8:33::5", wantCode: OK},
		{name: "below-private-172", dst: "172.15.255.254", wantCode: OK},
		{name: "above-private-172", dst: "172.32.0.1", wantCode: OK},
		{name: "below-ula", dst: "fb00::1", wantCode: OK},
		{name: "above-ula", dst: "fe00::1", wantCode: OK},
		{name: "last-octet-255", dst: "192.0.2.255", wantCode: OK},

		// Loopback.
		{name: "loopback-v4", dst: "127.0.0.1", wantCode: DisallowedDestination},
		{name: "loopback-v4-other", dst: "127.1.2.3", wantCode: DisallowedDestination},
		{name: "loopback-v6", dst: "::1", wantCode: DisallowedDestination},

		// Multicast.
		{name: "multicast-v4", dst: "224.0.0.1", wantCode: DisallowedDestination},
		{name: "multicast-v4-ssdp", dst: "239.255.255.250", wantCode: DisallowedDestination},
		{name: "multicast-v6", dst: "ff02::1", wantCode: DisallowedDestination},

		// Unspecified, which Linux connect() treats as localhost.
		{name: "unspecified-v4", dst: "0.0.0.0", wantCode: DisallowedDestination},
		{name: "unspecified-v6", dst: "::", wantCode: DisallowedDestination},

		// Limited broadcast.
		{name: "broadcast-v4", dst: "255.255.255.255", wantCode: DisallowedDestination},

		// Link-local unicast.
		{name: "link-local-v4", dst: "169.254.0.1", wantCode: DisallowedDestination},
		{name: "link-local-v6", dst: "fe80::1", wantCode: DisallowedDestination},

		// IPv4-in-IPv6 destinations are canonicalized by
		// [Conn25.handleConnectorTransitIPRequest] before they reach any of
		// these checks, so they are judged as the IPv4 address they map to
		// rather than refused outright for being 4-in-6.
		{name: "v4-in-v6-routable", dst: "::ffff:192.0.2.6", wantCode: OK},
		{name: "v4-in-v6-private", dst: "::ffff:10.1.2.3", wantCode: DisallowedDestination},
		{name: "v4-in-v6-magic-pool", dst: "::ffff:203.0.113.6", wantCode: DisallowedDestination},

		// Tailscale addresses, which would make the connector proxy back into
		// the tailnet.
		{name: "tailscale-cgnat", dst: "100.64.0.1", wantCode: DisallowedDestination},
		{name: "tailscale-service-ip", dst: "100.100.100.100", wantCode: DisallowedDestination},
		{name: "tailscale-ula", dst: "fd7a:115c:a1e0::1", wantCode: DisallowedDestination},

		// Cloud instance metadata.
		{name: "metadata-standard-v4", dst: "169.254.169.254", wantCode: DisallowedDestination},
		{name: "metadata-scaleway", dst: "169.254.42.42", wantCode: DisallowedDestination},
		{name: "metadata-alibaba", dst: "100.100.100.200", wantCode: DisallowedDestination},
		{name: "metadata-aws", dst: "fd00:ec2::254", wantCode: DisallowedDestination},
		{name: "metadata-gcp", dst: "fd20:ce::254", wantCode: DisallowedDestination},

		// Private addresses, which would let a client reach into the
		// connector's own network.
		{name: "private-10", dst: "10.1.2.3", wantCode: DisallowedDestination},
		{name: "private-172", dst: "172.16.0.9", wantCode: DisallowedDestination},
		{name: "private-172-high", dst: "172.31.255.254", wantCode: DisallowedDestination},
		{name: "private-192", dst: "192.168.1.1", wantCode: DisallowedDestination},
		{name: "ula-fc", dst: "fc00::1", wantCode: DisallowedDestination},
		{name: "ula-fd", dst: "fd12:3456:789a::1", wantCode: DisallowedDestination},

		// conn25's own address space.
		{name: "magic-pool-v4", dst: "203.0.113.5", wantCode: DisallowedDestination},
		{name: "transit-pool-v4", dst: "198.51.100.7", wantCode: DisallowedDestination},
		{name: "magic-pool-v6", dst: "2001:db8:11::5", wantCode: DisallowedDestination},
		{name: "transit-pool-v6", dst: "2001:db8:22::7", wantCode: DisallowedDestination},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := netip.MustParseAddr(tt.dst)
			// The handler canonicalizes the destination before checking it,
			// so the address family to match and the mapping to expect both
			// follow the unmapped form.
			unmapped := dst.Unmap()

			// Give each case its own transit IP, from the pool of the
			// destination's address family, so that the family check passes
			// and cases can't disturb each other's mappings.
			peerIP, transit := peerV6, netip.MustParseAddr("2001:db8:22::").As16()
			transit[15] = byte(1 + i)
			transitIP := netip.AddrFrom16(transit)
			if unmapped.Is4() {
				peerIP = peerV4
				transitIP = netip.AddrFrom4([4]byte{198, 51, 100, byte(1 + i)})
			}

			resp := c.handleConnectorTransitIPRequest(peerNode, peerCap, ConnectorTransitIPRequest{
				TransitIPs: []TransitIPRequest{{TransitIP: transitIP, DestinationIP: dst, App: appName}},
			})
			if len(resp.TransitIPs) != 1 {
				t.Fatalf("got %d responses, want 1", len(resp.TransitIPs))
			}
			if got := resp.TransitIPs[0].Code; got != tt.wantCode {
				t.Errorf("code = %d, want %d", got, tt.wantCode)
			}
			wantMessage := ""
			if tt.wantCode == DisallowedDestination {
				wantMessage = disallowedDestinationMessage
			}
			if got := resp.TransitIPs[0].Message; got != wantMessage {
				t.Errorf("message = %q, want %q", got, wantMessage)
			}

			// A refused request must not leave a mapping behind for the
			// datapath to find.
			var wantDst netip.Addr
			if tt.wantCode == OK {
				wantDst = unmapped
			}
			if got, _ := c.connector.lookupAddrBySrcIPAndTransitIP(peerIP, transitIP); got != wantDst {
				t.Errorf("lookup(%v, %v) = %v, want %v", peerIP, transitIP, got, wantDst)
			}
		})
	}
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

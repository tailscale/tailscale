// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"go4.org/mem"
	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/appctype"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/must"
	"tailscale.com/util/set"
)

func TestReserveIPs(t *testing.T) {
	c := newConn25(logger.Discard)
	const appName = "a"
	domainStr := "example.com."
	cfg := &config{
		isConfigured: true,
		appsByName:   map[string]appctype.Conn25Attr{appName: {}},
		ipSets: ipSets{
			v4Magic:   mustIPSetFromPrefix("100.64.0.0/24"),
			v6Magic:   mustIPSetFromPrefix("fd7a:115c:a1e0:a99c:0100::/80"),
			v4Transit: mustIPSetFromPrefix("169.254.0.0/24"),
			v6Transit: mustIPSetFromPrefix("fd7a:115c:a1e0:a99c:0200::/80"),
		},
	}
	c.reconfig(cfg)
	domain := must.Get(dnsname.ToFQDN(domainStr))

	for _, tt := range []struct {
		name        string
		dst         netip.Addr
		wantMagic   netip.Addr
		wantTransit netip.Addr
	}{
		{
			name:        "v4",
			dst:         netip.MustParseAddr("0.0.0.1"),
			wantMagic:   netip.MustParseAddr("100.64.0.0"),  // first from magic pool
			wantTransit: netip.MustParseAddr("169.254.0.0"), // first from transit pool
		},
		{
			name:        "v6",
			dst:         netip.MustParseAddr("::1"),
			wantMagic:   netip.MustParseAddr("fd7a:115c:a1e0:a99c:100::"), // first from magic pool
			wantTransit: netip.MustParseAddr("fd7a:115c:a1e0:a99c:200::"), // first from transit pool
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			addrs, err := c.client.reserveAddresses(appName, domain, tt.dst, 10)
			if err != nil {
				t.Fatal(err)
			}
			if tt.dst != addrs.dst {
				t.Errorf("want %v, got %v", tt.dst, addrs.dst)
			}
			if tt.wantMagic != addrs.magic {
				t.Errorf("want %v, got %v", tt.wantMagic, addrs.magic)
			}
			if tt.wantTransit != addrs.transit {
				t.Errorf("want %v, got %v", tt.wantTransit, addrs.transit)
			}
			if appName != addrs.app {
				t.Errorf("want %s, got %s", appName, addrs.app)
			}
			if domain != addrs.domain {
				t.Errorf("want %s, got %s", domain, addrs.domain)
			}
		})
	}
}

func TestReserveAddressesDeduplicated(t *testing.T) {
	for _, tt := range []struct {
		name string
		dst  netip.Addr
	}{
		{
			name: "v4",
			dst:  netip.MustParseAddr("0.0.0.1"),
		},
		{
			name: "v6",
			dst:  netip.MustParseAddr("::1"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const appName = "a"
			conn25 := newConn25(t.Logf)
			c := conn25.client
			c.v4MagicIPPool = newIPPool(mustIPSetFromPrefix("100.64.0.0/24"))
			c.v6MagicIPPool = newIPPool(mustIPSetFromPrefix("fd7a:115c:a1e0:a99c:0100::/80"))
			c.v4TransitIPPool = newIPPool(mustIPSetFromPrefix("169.254.0.0/24"))
			c.v6TransitIPPool = newIPPool(mustIPSetFromPrefix("fd7a:115c:a1e0:a99c:0200::/80"))

			first, err := c.reserveAddresses(appName, "example.com.", tt.dst, 10)
			if err != nil {
				t.Fatal(err)
			}

			second, err := c.reserveAddresses(appName, "example.com.", tt.dst, 10)
			if err != nil {
				t.Fatal(err)
			}

			if first != second {
				// reserveAddresses should return the existing entry when called for a domain that already has assigned addrs
				t.Fatalf("want first==second, got first: %v, second: %v", first, second)
			}

			if got := len(c.assignments.byMagicIP); got != 1 {
				t.Errorf("want 1 entry in byMagicIP, got %d", got)
			}
			if got := len(c.assignments.byDomainDst); got != 1 {
				t.Errorf("want 1 entry in byDomainDst, got %d", got)
			}
		})
	}
}

func TestTransitIPConnMapping(t *testing.T) {
	conn25 := newConn25(t.Logf)

	as := &addrs{
		dst:     netip.MustParseAddr("1.2.3.1"),
		magic:   netip.MustParseAddr("100.64.0.1"),
		transit: netip.MustParseAddr("169.254.0.1"),
		domain:  "woo.example.com.",
		app:     "app1",
	}

	connectorPeers := []tailcfg.NodeView{
		(&tailcfg.Node{
			ID:       tailcfg.NodeID(0),
			Tags:     []string{"tag:woo"},
			Hostinfo: (&tailcfg.Hostinfo{AppConnector: opt.NewBool(true)}).View(),
			Key:      key.NodePublic{},
		}).View(),
		(&tailcfg.Node{
			ID:       tailcfg.NodeID(2),
			Tags:     []string{"tag:hoo"},
			Hostinfo: (&tailcfg.Hostinfo{AppConnector: opt.NewBool(true)}).View(),
			Key:      key.NodePublicFromRaw32(mem.B([]byte{0: 0xff, 31: 0x02})),
		}).View(),
	}

	// Adding a transit IP that isn't known should fail
	if err := conn25.client.addTransitIPForConnector(as.transit, connectorPeers[1]); err == nil {
		t.Error("adding an unknown transit IP should fail")
	}

	// Insert the address assignments
	conn25.client.assignments.insert(as)

	// Adding a transit IP for a node with an unset key should fail
	if err := conn25.client.addTransitIPForConnector(as.transit, connectorPeers[0]); err == nil {
		t.Error("adding an transit IP mapping for a connector with a zero key should fail")
	}
	// Adding a transit IP that is known should succeed
	if err := conn25.client.addTransitIPForConnector(as.transit, connectorPeers[1]); err != nil {
		t.Errorf("unexpected error for first time add: %v", err)
	}
	// And doing it again shouldn't fail (this is done when resending mappings
	// to a restarted connector)
	if err := conn25.client.addTransitIPForConnector(as.transit, connectorPeers[1]); err != nil {
		t.Errorf("error adding duplicate transitIP for a connector: %v", err)
	}
}

func TestIsKnownTransitIP(t *testing.T) {
	knownTip := netip.MustParseAddr("100.64.0.41")
	unknownTip := netip.MustParseAddr("100.64.0.42")

	c := newConn25(t.Logf)
	err := c.client.assignments.insert(&addrs{
		transit: knownTip,
	})
	if err != nil {
		t.Errorf("error inserting address assignment: %v", err)
		return
	}

	if !c.client.isKnownTransitIP(knownTip) {
		t.Fatal("knownTip: should have been known")
	}
	if c.client.isKnownTransitIP(unknownTip) {
		t.Fatal("unknownTip: should not have been known")
	}
}

func TestLinkLocalAllow(t *testing.T) {
	knownTip := netip.MustParseAddr("100.64.0.41")

	c := newConn25(t.Logf)
	err := c.client.assignments.insert(&addrs{
		transit: knownTip,
	})
	if err != nil {
		t.Fatalf("error inserting address assignment: %v", err)
	}

	if allow, _ := c.client.linkLocalAllow(packet.Parsed{
		Dst: netip.AddrPortFrom(knownTip, 1234),
	}); !allow {
		t.Fatal("knownTip: should have been allowed")
	}

	if allow, _ := c.client.linkLocalAllow(packet.Parsed{
		Dst: netip.AddrPort{},
	}); allow {
		t.Fatal("unknownTip: should not have been allowed")
	}
}

func TestReconfigDoesNotReissueInUseAddresses(t *testing.T) {
	appName := "app1"
	mustRange := func(from, to string) netipx.IPRange {
		return netipx.IPRangeFrom(netip.MustParseAddr(from), netip.MustParseAddr(to))
	}
	beforeRangeV4 := mustRange("0.0.0.1", "0.0.0.3")
	beforeRangeV6 := mustRange("::1", "::3")
	afterRangeV4 := mustRange("0.0.0.4", "0.0.0.7")
	afterRangeV6 := mustRange("::4", "::7")
	makeNodeFromMagicRange := func(v4, v6 netipx.IPRange) tailcfg.NodeView {
		return makeSelfNode(t, []appctype.Conn25Attr{{
			Name:       appName,
			Connectors: []string{"tag:woo"},
			Domains:    []string{"example.com"},
		}}, appctype.Conn25PoolsAttr{
			V4MagicIPPool:   []netipx.IPRange{v4},
			V6MagicIPPool:   []netipx.IPRange{v6},
			V4TransitIPPool: []netipx.IPRange{mustRange("169.254.0.0", "169.254.0.10")},
			V6TransitIPPool: []netipx.IPRange{mustRange("fd7a:115c:a1e0:a99c:0200::", "fd7a:115c:a1e0:a99c:0200::10")},
		}, []string{})
	}
	domain := must.Get(dnsname.ToFQDN("example.com."))

	for _, tt := range []struct {
		name   string
		dstOne netip.Addr
		dstTwo netip.Addr
	}{
		{
			name:   "v4",
			dstOne: netip.MustParseAddr("0.0.0.100"),
			dstTwo: netip.MustParseAddr("0.0.0.101"),
		},
		{
			name:   "v6",
			dstOne: netip.MustParseAddr("::100"),
			dstTwo: netip.MustParseAddr("::101"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newConn25(t.Logf)
			ext := &extension{
				conn25: c,
			}

			_, err := c.client.reserveAddresses(appName, domain, tt.dstOne, 10)
			if !errors.Is(err, errUninitializedIPPool) {
				t.Fatalf("want %v, got %v", errUninitializedIPPool, err)
			}

			ext.onSelfChange(makeNodeFromMagicRange(beforeRangeV4, beforeRangeV6))
			beforeAddrs, err := c.client.reserveAddresses(appName, domain, tt.dstOne, 10)
			if err != nil {
				t.Fatal(err)
			}
			ext.onSelfChange(makeNodeFromMagicRange(afterRangeV4, afterRangeV6))
			afterAddrs, err := c.client.reserveAddresses(appName, domain, tt.dstTwo, 10)
			if err != nil {
				t.Fatal(err)
			}
			if afterAddrs.magic == beforeAddrs.magic {
				t.Errorf("pool reissued magic: %v that was already assigned", beforeAddrs.magic)
			}
		})
	}
}

// TestAddressExpiryDependsOnActiveFlows creates a Conn25 and
//
//  1. runs a DNS response through it
//  2. uses the ClientFlowCreated/Removed API and advances the clock
//  3. runs a second DNS response through the Conn25
//  4. asserts things about the expected state of the clients assignments
//     table based on 1-3
//
// to try and verify how the assignments table entries expiration is affected
// by the presence of active flows for the addresses in the entry
func TestAddressExpiryDependsOnActiveFlows(t *testing.T) {
	configuredDomain := "example.com"
	domainName := configuredDomain + "."
	dnsMessageName := dnsmessage.MustNewName(domainName)
	sn := makeSelfNode(t, []appctype.Conn25Attr{{
		Name:       "app1",
		Connectors: []string{"tag:woo"},
		Domains:    []string{configuredDomain},
	}}, arbitraryPools, nil)

	var ttlSecs uint32 = 300
	ttlDur := time.Duration(ttlSecs) * time.Second

	ipOne := netip.MustParseAddr("1.0.0.1")
	dnsRespIPOne := makeDNSResponseForSections(
		t,
		[]dnsmessage.Question{{Name: dnsMessageName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		[]dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: dnsMessageName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttlSecs},
				Body:   &dnsmessage.AResource{A: ipOne.As4()},
			},
		},
		nil,
	)

	ipTwo := netip.MustParseAddr("1.0.0.2")
	dnsRespIPTwo := makeDNSResponseForSections(
		t,
		[]dnsmessage.Question{{Name: dnsMessageName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		[]dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: dnsMessageName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttlSecs},
				Body:   &dnsmessage.AResource{A: ipTwo.As4()},
			},
		},
		nil,
	)

	tests := []struct {
		name                    string
		flowsAndTimeFx          func(*Conn25, *tstest.Clock, netip.Addr)
		secondDNSResponse       []byte
		assertSecondDNSResponse func(*testing.T, []byte)
		wantUnexpiredDstIPs     set.Set[netip.Addr]
		wantExpiredAtTime       map[netip.Addr]time.Duration // since the startTime
	}{
		{
			// The first dns response should create an assignments entry for ipOne
			// (tested elsewhere).
			// Then time advances past that entry's expiresAt.
			// Then a second dns response creates an assignments entry for ipTwo.
			// We clean up some expired assignments entries when we create a new one
			// and so we expect the entry for ipOne to be removed, and the entry for
			// ipTwo to be present.
			name: "flows-zero",
			flowsAndTimeFx: func(c *Conn25, clock *tstest.Clock, transit netip.Addr) {
				clock.Advance(30 * time.Hour)
			},
			wantUnexpiredDstIPs: set.SetOf([]netip.Addr{ipTwo}),
			wantExpiredAtTime: map[netip.Addr]time.Duration{
				ipTwo: (30 * time.Hour) + ttlDur,
			},
		},
		{
			// Same as flows-zero except this time the datapath has let us know that
			// there is a flow for the transit address that was assigned to the entry for
			// ipOne.
			// And so that entry does not get expired.
			name: "flows-not-zero",
			flowsAndTimeFx: func(c *Conn25, clock *tstest.Clock, transit netip.Addr) {
				c.ClientFlowCreated(transit)
				clock.Advance(30 * time.Hour)
			},
			wantUnexpiredDstIPs: set.SetOf([]netip.Addr{ipOne, ipTwo}),
			wantExpiredAtTime: map[netip.Addr]time.Duration{
				ipOne: (30 * time.Hour) + extendForActiveFlowDuration,
				ipTwo: (30 * time.Hour) + ttlDur,
			},
		},
		{
			// Like flows-not-zero except that this time the datapath removed the
			// client flow after creating it.
			// So the expired entry is removed.
			name: "last-flow-removed-a-while-ago",
			flowsAndTimeFx: func(c *Conn25, clock *tstest.Clock, transit netip.Addr) {
				c.ClientFlowCreated(transit)
				clock.Advance(30 * time.Hour)
				c.ClientFlowRemoved(transit)
				clock.Advance(3 * time.Minute)
			},
			wantUnexpiredDstIPs: set.SetOf([]netip.Addr{ipTwo}),
			wantExpiredAtTime: map[netip.Addr]time.Duration{
				ipTwo: (30 * time.Hour) + (3 * time.Minute) + ttlDur,
			},
		},
		{
			// Like last-flow-removed-a-while-ago except the flow was removed recently,
			// within the cooldown period.
			// And so the expired entry is not removed.
			name: "last-flow-recently-removed",
			flowsAndTimeFx: func(c *Conn25, clock *tstest.Clock, transit netip.Addr) {
				c.ClientFlowCreated(transit)
				clock.Advance(30 * time.Hour)
				c.ClientFlowRemoved(transit)
				clock.Advance(1 * time.Second)
			},
			wantUnexpiredDstIPs: set.SetOf([]netip.Addr{ipOne, ipTwo}),
			wantExpiredAtTime: map[netip.Addr]time.Duration{
				ipOne: (30 * time.Hour) + extendForActiveFlowDuration + (1 * time.Second),
				ipTwo: (30 * time.Hour) + (1 * time.Second) + ttlDur,
			},
		},
		{
			// Like flows-not-zero except that the second dns response is for the same address as the first.
			// So the entry is not removed.
			name:              "repeated-response-with-expired-and-active-flow",
			secondDNSResponse: dnsRespIPOne,
			flowsAndTimeFx: func(c *Conn25, clock *tstest.Clock, transit netip.Addr) {
				c.ClientFlowCreated(transit)
				clock.Advance(30 * time.Hour)
			},
			wantUnexpiredDstIPs: set.SetOf([]netip.Addr{ipOne}),
			wantExpiredAtTime: map[netip.Addr]time.Duration{
				ipOne: (30 * time.Hour) + ttlDur,
			},
			assertSecondDNSResponse: assertParsesToAnswers(
				[]netip.Addr{
					netip.MustParseAddr("100.64.0.0"),
				},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newConn25(logger.Discard)
			startTime := time.Now()
			clock := tstest.NewClock(tstest.ClockOpts{Start: startTime})
			c.client.assignments.clock = clock
			cfg := mustConfig(t, sn)
			c.reconfig(cfg)

			// we get a dns response for ipone
			bs1 := c.mapDNSResponse(dnsRespIPOne)
			assertParsesToAnswers(
				[]netip.Addr{
					netip.MustParseAddr("100.64.0.0"),
				},
			)(t, bs1)

			ipOneDD := domainDst{
				domain: dnsname.FQDN(domainName),
				dst:    ipOne,
			}

			// there are client flows and time passes
			tt.flowsAndTimeFx(c, clock, c.client.assignments.byDomainDst[ipOneDD].transit)

			// then a second dns response
			dnsR2 := tt.secondDNSResponse
			assertSecondResponseFx := tt.assertSecondDNSResponse
			if dnsR2 == nil {
				dnsR2 = dnsRespIPTwo
				assertSecondResponseFx = assertParsesToAnswers(
					[]netip.Addr{
						netip.MustParseAddr("100.64.0.1"),
					},
				)
			}
			bs2 := c.mapDNSResponse(dnsR2)
			assertSecondResponseFx(t, bs2)

			// assert which addresses have expired / remain unexpired
			assignmentsDsts := set.Set[netip.Addr]{}
			for _, a := range c.client.assignments.byMagicIP {
				assignmentsDsts.Add(a.dst)
			}
			if !assignmentsDsts.Equal(tt.wantUnexpiredDstIPs) {
				t.Fatalf("unexpired dst IPs: want: %v, got %v", tt.wantUnexpiredDstIPs, assignmentsDsts)
			}

			for a, dur := range tt.wantExpiredAtTime {
				dd := domainDst{
					domain: dnsname.FQDN(domainName),
					dst:    a,
				}
				as := c.client.assignments.byDomainDst[dd]
				expected := startTime.Add(dur)
				if !as.expiresAt.Equal(expected) {
					t.Fatalf("a: %v, as.ExpiredAt: %v, expected: %v, dur: %v", a, as.expiresAt, expected, dur)
				}
			}
		})
	}
}

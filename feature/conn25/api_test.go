// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/must"
)

func TestGetActiveState(t *testing.T) {
	mustFQDN := func(s string) dnsname.FQDN { return must.Get(dnsname.ToFQDN(s)) }
	// Fixed, arbitrary expiry so the output is comparable.
	expires := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

	t.Run("unconfigured", func(t *testing.T) {
		c := newConn25(logger.Discard)
		if diff := cmp.Diff(appctype.Conn25ActiveState{}, c.GetActiveState()); diff != "" {
			t.Fatalf("unconfigured Conn25ActiveState mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("configured", func(t *testing.T) {
		c := newConn25(logger.Discard)
		c.config.Store(&config{isConfigured: true})

		client := c.client
		client.assignments.byDomainDst = map[domainDst]*addrs{}
		addClientAssignment := func(app, domain, dst, magic, transit string, flows int) {
			as := &addrs{
				app:             app,
				domain:          mustFQDN(domain),
				dst:             netip.MustParseAddr(dst),
				magic:           netip.MustParseAddr(magic),
				transit:         netip.MustParseAddr(transit),
				activeFlowCount: flows,
				expiresAt:       expires,
			}
			client.assignments.byDomainDst[domainDst{domain: as.domain, dst: as.dst}] = as
		}
		// Two addresses under app1/example.com: should sort by active flow
		// count descending (5 before 2).
		addClientAssignment("app1", "example.com", "10.0.0.1", "100.64.0.1", "169.254.0.1", 2)
		addClientAssignment("app1", "example.com", "10.0.0.2", "100.64.0.2", "169.254.0.2", 5)
		// example.com (2 labels) sorts before sub.example.com.
		addClientAssignment("app1", "sub.example.com", "10.0.0.3", "100.64.0.3", "169.254.0.3", 1)
		// A second app: apps sort by name, so app1 before zebra.
		addClientAssignment("zebra", "z.example.org", "10.0.0.4", "100.64.0.4", "169.254.0.4", 1)

		// IP addresses should be sorted numerically, not lexigraphically.
		c.connector.transitIPs = map[netip.Addr]map[netip.Addr]appAddr{
			netip.MustParseAddr("100.64.0.1"): {
				netip.MustParseAddr("169.254.0.100"): {app: "app1", addr: netip.MustParseAddr("10.0.0.100")},
				netip.MustParseAddr("169.254.0.11"):  {app: "app1", addr: netip.MustParseAddr("10.0.0.11")},
			},
			netip.MustParseAddr("11.0.0.1"): {
				netip.MustParseAddr("169.254.0.5"): {app: "zapp", addr: netip.MustParseAddr("10.0.0.5")},
				netip.MustParseAddr("169.254.0.6"): {app: "app1", addr: netip.MustParseAddr("10.0.0.6")},
			},
		}

		// Configure the four IP pools with distinct capacities and hand out a
		// distinct number of addresses from each.
		mustPool := func(prefix string, handOut int) *ippool {
			p := newIPPool(mustIPSetFromPrefix(prefix))
			for range handOut {
				if _, err := p.next(); err != nil {
					t.Fatal(err)
				}
			}
			return p
		}
		client.v4MagicIPPool = mustPool("100.64.0.0/30", 1)    // capacity 4
		client.v6MagicIPPool = mustPool("fd7a:1::/125", 2)     // capacity 8
		client.v4TransitIPPool = mustPool("169.254.0.0/28", 3) // capacity 16
		client.v6TransitIPPool = mustPool("fd7a:2::/123", 4)   // capacity 32

		want := appctype.Conn25ActiveState{
			Configured: true,
			Client: appctype.Conn25ClientState{
				Apps: []appctype.Conn25ClientAppState{
					{
						App: "app1",
						Domains: []appctype.Conn25ClientDomainState{
							{
								Domain: mustFQDN("example.com"),
								Addresses: []appctype.Conn25ClientAddressState{
									{ActiveFlowCount: 5, DestinationIP: "10.0.0.2", MagicIP: "100.64.0.2", TransitIP: "169.254.0.2", ExpiresAt: expires},
									{ActiveFlowCount: 2, DestinationIP: "10.0.0.1", MagicIP: "100.64.0.1", TransitIP: "169.254.0.1", ExpiresAt: expires},
								},
							},
							{
								Domain: mustFQDN("sub.example.com"),
								Addresses: []appctype.Conn25ClientAddressState{
									{ActiveFlowCount: 1, DestinationIP: "10.0.0.3", MagicIP: "100.64.0.3", TransitIP: "169.254.0.3", ExpiresAt: expires},
								},
							},
						},
					},
					{
						App: "zebra",
						Domains: []appctype.Conn25ClientDomainState{
							{
								Domain: mustFQDN("z.example.org"),
								Addresses: []appctype.Conn25ClientAddressState{
									{ActiveFlowCount: 1, DestinationIP: "10.0.0.4", MagicIP: "100.64.0.4", TransitIP: "169.254.0.4", ExpiresAt: expires},
								},
							},
						},
					},
				},
				IPPoolStats: appctype.Conn25ClientIPPoolStats{
					IPv4MagicIPsInUse:      1,
					IPv4MagicIPsCapacity:   4,
					IPv6MagicIPsInUse:      2,
					IPv6MagicIPsCapacity:   8,
					IPv4TransitIPsInUse:    3,
					IPv4TransitIPsCapacity: 16,
					IPv6TransitIPsInUse:    4,
					IPv6TransitIPsCapacity: 32,
				},
			},
			Connector: appctype.Conn25ConnectorState{
				Peers: []appctype.Conn25ConnectorPeerState{
					{
						ClientIP: "11.0.0.1",
						Apps: []appctype.Conn25ConnectorAppState{
							{App: "app1", Addresses: []appctype.Conn25ConnectorAddressState{{DestinationIP: "10.0.0.6", TransitIP: "169.254.0.6"}}},
							{App: "zapp", Addresses: []appctype.Conn25ConnectorAddressState{{DestinationIP: "10.0.0.5", TransitIP: "169.254.0.5"}}},
						},
					},
					{
						ClientIP: "100.64.0.1",
						Apps: []appctype.Conn25ConnectorAppState{
							{App: "app1", Addresses: []appctype.Conn25ConnectorAddressState{
								{DestinationIP: "10.0.0.11", TransitIP: "169.254.0.11"},
								{DestinationIP: "10.0.0.100", TransitIP: "169.254.0.100"},
							}},
						},
					},
				},
			},
		}

		got := c.GetActiveState()
		if diff := cmp.Diff(want, got, cmpopts.EquateApproxTime(0)); diff != "" {
			t.Fatalf("Conn25ActiveState mismatch (-want +got):\n%s", diff)
		}
	})
}

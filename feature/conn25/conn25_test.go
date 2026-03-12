// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/must"
	"tailscale.com/util/set"
)

func mustIPSetFromPrefix(s string) *netipx.IPSet {
	b := &netipx.IPSetBuilder{}
	b.AddPrefix(netip.MustParsePrefix(s))
	set, err := b.IPSet()
	if err != nil {
		panic(err)
	}
	return set
}

// TestHandleConnectorTransitIPRequest tests that if sent a
// request with a transit addr and a destination addr we store that mapping
// and can retrieve it.
func TestHandleConnectorTransitIPRequest(t *testing.T) {

	const appName = "TestApp"

	// Peer IPs
	pipV4_1 := netip.MustParseAddr("100.101.101.101")
	pipV4_2 := netip.MustParseAddr("100.101.101.102")

	pipV6_1 := netip.MustParseAddr("fd7a:115c:a1e0::101")
	pipV6_3 := netip.MustParseAddr("fd7a:115c:a1e0::103")

	// Transit IPs
	tipV4_1 := netip.MustParseAddr("0.0.0.1")
	tipV4_2 := netip.MustParseAddr("0.0.0.2")

	tipV6_1 := netip.MustParseAddr("FE80::1")

	// Destination IPs
	dipV4_1 := netip.MustParseAddr("10.0.0.1")
	dipV4_2 := netip.MustParseAddr("10.0.0.2")
	dipV4_3 := netip.MustParseAddr("10.0.0.3")

	dipV6_1 := netip.MustParseAddr("fc00::1")

	// Peer nodes
	peerV4V6 := (&tailcfg.Node{
		ID:        tailcfg.NodeID(1),
		Addresses: []netip.Prefix{netip.PrefixFrom(pipV4_1, 32), netip.PrefixFrom(pipV6_1, 128)},
	}).View()

	peerV4Only := (&tailcfg.Node{
		ID:        tailcfg.NodeID(2),
		Addresses: []netip.Prefix{netip.PrefixFrom(pipV4_2, 32)},
	}).View()

	peerV6Only := (&tailcfg.Node{
		ID:        tailcfg.NodeID(3),
		Addresses: []netip.Prefix{netip.PrefixFrom(pipV6_3, 128)},
	}).View()

	tests := []struct {
		name         string
		ctipReqPeers []tailcfg.NodeView           // One entry per request and the other
		ctipReqs     []ConnectorTransitIPRequest  // arrays in this struct must have the same
		wants        []ConnectorTransitIPResponse // cardinality
		// For checking lookups:
		//	The outer array needs to correspond to the number of requests,
		//	can be nil if no lookups need to be done after the request is processed.
		//
		//	The middle array is the set of lookups for the corresponding request.
		//
		//	The inner array is a tuple of (PeerIP, TransitIP, ExpectedDestinationIP)
		wantLookups [][][]netip.Addr
	}{
		// Single peer, single request with success ipV4
		{
			name:         "one-peer-one-req-ipv4",
			ctipReqPeers: []tailcfg.NodeView{peerV4Only},
			ctipReqs: []ConnectorTransitIPRequest{
				{TransitIPs: []TransitIPRequest{{TransitIP: tipV4_1, DestinationIP: dipV4_1, App: appName}}},
			},
			wants: []ConnectorTransitIPResponse{
				{TransitIPs: []TransitIPResponse{{Code: OK, Message: ""}}},
			},
			wantLookups: [][][]netip.Addr{
				{{pipV4_2, tipV4_1, dipV4_1}},
			},
		},
		// Single peer, single request with success ipV6
		{
			name:         "one-peer-one-req-ipv6",
			ctipReqPeers: []tailcfg.NodeView{peerV6Only},
			ctipReqs: []ConnectorTransitIPRequest{
				{TransitIPs: []TransitIPRequest{{TransitIP: tipV6_1, DestinationIP: dipV6_1, App: appName}}},
			},
			wants: []ConnectorTransitIPResponse{
				{TransitIPs: []TransitIPResponse{{Code: OK, Message: ""}}},
			},
			wantLookups: [][][]netip.Addr{
				{{pipV6_3, tipV6_1, dipV6_1}},
			},
		},
		// Single peer, multi request with success, ipV4
		{
			name:         "one-peer-multi-req-ipv4",
			ctipReqPeers: []tailcfg.NodeView{peerV4Only, peerV4Only},
			ctipReqs: []ConnectorTransitIPRequest{
				{TransitIPs: []TransitIPRequest{{TransitIP: tipV4_1, DestinationIP: dipV4_1, App: appName}}},
				{TransitIPs: []TransitIPRequest{{TransitIP: tipV4_2, DestinationIP: dipV4_2, App: appName}}},
			},
			wants: []ConnectorTransitIPResponse{
				{TransitIPs: []TransitIPResponse{{Code: OK, Message: ""}}},
				{TransitIPs: []TransitIPResponse{{Code: OK, Message: ""}}},
			},
			wantLookups: [][][]netip.Addr{
				{{pipV4_2, tipV4_1, dipV4_1}},
				{{pipV4_2, tipV4_2, dipV4_2}},
			},
		},
		// Single peer, multi request remap tip, ipV4
		{
			name:         "one-peer-remap-tip",
			ctipReqPeers: []tailcfg.NodeView{peerV4Only, peerV4Only},
			ctipReqs: []ConnectorTransitIPRequest{
				{TransitIPs: []TransitIPRequest{{TransitIP: tipV4_1, DestinationIP: dipV4_1, App: appName}}},
				{TransitIPs: []TransitIPRequest{{TransitIP: tipV4_1, DestinationIP: dipV4_2, App: appName}}},
			},
			wants: []ConnectorTransitIPResponse{
				{TransitIPs: []TransitIPResponse{{Code: OK, Message: ""}}},
				{TransitIPs: []TransitIPResponse{{Code: OK, Message: ""}}},
			},
			wantLookups: [][][]netip.Addr{
				{{pipV4_2, tipV4_1, dipV4_1}},
				{{pipV4_2, tipV4_1, dipV4_2}},
			},
		},
		// Single peer, multi request with success, ipV4 and ipV6
		{
			name:         "one-peer-multi-req-ipv4-ipv6",
			ctipReqPeers: []tailcfg.NodeView{peerV4V6, peerV4V6},
			ctipReqs: []ConnectorTransitIPRequest{
				{TransitIPs: []TransitIPRequest{{TransitIP: tipV4_1, DestinationIP: dipV4_1, App: appName}}},
				{TransitIPs: []TransitIPRequest{{TransitIP: tipV6_1, DestinationIP: dipV6_1, App: appName}}},
			},
			wants: []ConnectorTransitIPResponse{
				{TransitIPs: []TransitIPResponse{{Code: OK, Message: ""}}},
				{TransitIPs: []TransitIPResponse{{Code: OK, Message: ""}}},
			},
			wantLookups: [][][]netip.Addr{
				{{pipV4_1, tipV4_1, dipV4_1}},
				{{pipV4_1, tipV4_1, dipV4_1}, {pipV6_1, tipV6_1, dipV6_1}, {pipV4_1, tipV6_1, netip.Addr{}}},
			},
		},
		// Single peer, multi map with success, ipV4
		{
			name:         "one-peer-multi-map-ipv4",
			ctipReqPeers: []tailcfg.NodeView{peerV4Only},
			ctipReqs: []ConnectorTransitIPRequest{
				{TransitIPs: []TransitIPRequest{
					{TransitIP: tipV4_1, DestinationIP: dipV4_1, App: appName},
					{TransitIP: tipV4_2, DestinationIP: dipV4_2, App: appName},
				}},
			},
			wants: []ConnectorTransitIPResponse{
				{TransitIPs: []TransitIPResponse{{Code: OK, Message: ""}, {Code: OK, Message: ""}}},
			},
			wantLookups: [][][]netip.Addr{
				{{pipV4_2, tipV4_1, dipV4_1}, {pipV4_2, tipV4_2, dipV4_2}},
			},
		},
		// Single peer, error reuse same tip in one request, ensure all non-dup requests are processed
		{
			name:         "one-peer-multi-map-duplicate-tip",
			ctipReqPeers: []tailcfg.NodeView{peerV4Only},
			ctipReqs: []ConnectorTransitIPRequest{
				{TransitIPs: []TransitIPRequest{
					{TransitIP: tipV4_1, DestinationIP: dipV4_1, App: appName},
					{TransitIP: tipV4_1, DestinationIP: dipV4_2, App: appName},
					{TransitIP: tipV4_2, DestinationIP: dipV4_3, App: appName},
				}},
			},
			wants: []ConnectorTransitIPResponse{
				{TransitIPs: []TransitIPResponse{
					{Code: OK, Message: ""},
					{Code: DuplicateTransitIP, Message: dupeTransitIPMessage},
					{Code: OK, Message: ""}},
				},
			},
			wantLookups: [][][]netip.Addr{
				{{pipV4_2, tipV4_1, dipV4_1}, {pipV4_2, tipV4_2, dipV4_3}},
			},
		},
		// Multi peer, success reuse same tip in one request
		{
			name:         "multi-peer-duplicate-tip",
			ctipReqPeers: []tailcfg.NodeView{peerV4V6, peerV4Only},
			ctipReqs: []ConnectorTransitIPRequest{
				{TransitIPs: []TransitIPRequest{{TransitIP: tipV4_1, DestinationIP: dipV4_1, App: appName}}},
				{TransitIPs: []TransitIPRequest{{TransitIP: tipV4_1, DestinationIP: dipV4_2, App: appName}}},
			},
			wants: []ConnectorTransitIPResponse{
				{TransitIPs: []TransitIPResponse{{Code: OK, Message: ""}}},
				{TransitIPs: []TransitIPResponse{{Code: OK, Message: ""}}},
			},
			wantLookups: [][][]netip.Addr{
				{{pipV4_1, tipV4_1, dipV4_1}},
				{{pipV4_1, tipV4_1, dipV4_1}, {pipV4_2, tipV4_1, dipV4_2}},
			},
		},
		// Single peer, multi map, multiple tip to same dip
		{
			name:         "one-peer-multi-map-multi-tip-to-dip",
			ctipReqPeers: []tailcfg.NodeView{peerV4Only},
			ctipReqs: []ConnectorTransitIPRequest{
				{TransitIPs: []TransitIPRequest{
					{TransitIP: tipV4_1, DestinationIP: dipV4_1, App: appName},
					{TransitIP: tipV4_2, DestinationIP: dipV4_1, App: appName},
				}},
			},
			wants: []ConnectorTransitIPResponse{
				{TransitIPs: []TransitIPResponse{{Code: OK, Message: ""}, {Code: OK, Message: ""}}},
			},
			wantLookups: [][][]netip.Addr{
				{{pipV4_2, tipV4_1, dipV4_1}, {pipV4_2, tipV4_2, dipV4_1}},
			},
		},
		// Single peer, ipv4 tip, no ipv4 pip, but ipv6 tip works
		{
			name:         "one-peer-missing-ipv4-family",
			ctipReqPeers: []tailcfg.NodeView{peerV6Only},
			ctipReqs: []ConnectorTransitIPRequest{
				{TransitIPs: []TransitIPRequest{
					{TransitIP: tipV4_1, DestinationIP: dipV4_1, App: appName},
					{TransitIP: tipV6_1, DestinationIP: dipV6_1, App: appName},
				}},
			},
			wants: []ConnectorTransitIPResponse{
				{TransitIPs: []TransitIPResponse{
					{Code: NoMatchingPeerIPFamily, Message: noMatchingPeerIPFamilyMessage},
					{Code: OK, Message: ""},
				}},
			},
			wantLookups: [][][]netip.Addr{
				{{pipV6_3, tipV4_1, netip.Addr{}}, {pipV6_3, tipV6_1, dipV6_1}},
			},
		},
		// Single peer, ipv6 tip, no ipv6 pip, but ipv4 tip works
		{
			name:         "one-peer-missing-ipv6-family",
			ctipReqPeers: []tailcfg.NodeView{peerV4Only},
			ctipReqs: []ConnectorTransitIPRequest{
				{TransitIPs: []TransitIPRequest{
					{TransitIP: tipV6_1, DestinationIP: dipV6_1, App: appName},
					{TransitIP: tipV4_1, DestinationIP: dipV4_1, App: appName},
				}},
			},
			wants: []ConnectorTransitIPResponse{
				{TransitIPs: []TransitIPResponse{
					{Code: NoMatchingPeerIPFamily, Message: noMatchingPeerIPFamilyMessage},
					{Code: OK, Message: ""},
				}},
			},
			wantLookups: [][][]netip.Addr{
				{{pipV4_2, tipV6_1, netip.Addr{}}, {pipV4_2, tipV4_1, dipV4_1}},
			},
		},
		// Single peer, mismatched transit and destination ips
		{
			name:         "one-peer-mismatched-tip-dip",
			ctipReqPeers: []tailcfg.NodeView{peerV4Only},
			ctipReqs: []ConnectorTransitIPRequest{
				{TransitIPs: []TransitIPRequest{{TransitIP: tipV4_1, DestinationIP: dipV6_1, App: appName}}},
			},
			wants: []ConnectorTransitIPResponse{
				{TransitIPs: []TransitIPResponse{{Code: AddrFamilyMismatch, Message: addrFamilyMismatchMessage}}},
			},
			wantLookups: [][][]netip.Addr{
				{{pipV4_2, tipV4_1, netip.Addr{}}},
			},
		},
		// Single peer, invalid app name
		{
			name:         "one-peer-invalid-app",
			ctipReqPeers: []tailcfg.NodeView{peerV4Only},
			ctipReqs: []ConnectorTransitIPRequest{
				{TransitIPs: []TransitIPRequest{{TransitIP: tipV4_1, DestinationIP: dipV4_1, App: "Unknown App"}}},
			},
			wants: []ConnectorTransitIPResponse{
				{TransitIPs: []TransitIPResponse{{Code: UnknownAppName, Message: unknownAppNameMessage}}},
			},
			wantLookups: [][][]netip.Addr{
				{{pipV4_2, tipV4_1, netip.Addr{}}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch {
			case len(tt.ctipReqPeers) != len(tt.ctipReqs):
				t.Fatalf("error in test setup: ctipReqPeers has length %d does not match ctipReqs length %d",
					len(tt.ctipReqPeers), len(tt.ctipReqs))
			case len(tt.ctipReqPeers) != len(tt.wants):
				t.Fatalf("error in test setup: ctipReqPeers has length %d does not match wants length %d",
					len(tt.ctipReqPeers), len(tt.wants))
			case len(tt.ctipReqPeers) != len(tt.wantLookups):
				t.Fatalf("error in test setup: ctipReqPeers has length %d does not match wantLookups length %d",
					len(tt.ctipReqPeers), len(tt.wantLookups))
			}

			// Use the same Conn25 for each request in the test and seed it with a test app name.
			c := newConn25(logger.Discard)
			c.connector.config = config{
				appsByName: map[string]appctype.Conn25Attr{appName: {}},
			}

			for i, peer := range tt.ctipReqPeers {
				req := tt.ctipReqs[i]
				want := tt.wants[i]

				resp := c.handleConnectorTransitIPRequest(peer, req)

				// Ensure that we have the expected number of responses
				if len(resp.TransitIPs) != len(want.TransitIPs) {
					t.Fatalf("wrong number of TransitIPs in response %d: got %d, want %d",
						i, len(resp.TransitIPs), len(want.TransitIPs))
				}

				// Validate the contents of each response
				for j, tipResp := range resp.TransitIPs {
					wantResp := want.TransitIPs[j]
					if tipResp.Code != wantResp.Code {
						t.Errorf("transitIP.Code mismatch in response %d, tipresp %d: got %d, want %d",
							i, j, tipResp.Code, wantResp.Code)
					}
					if tipResp.Message != wantResp.Message {
						t.Errorf("transitIP.Message mismatch in response %d, tipresp %d: got %q, want %q",
							i, j, tipResp.Message, wantResp.Message)
					}
				}

				// Validate the state of the transitIP map after each request
				if tt.wantLookups[i] != nil {
					for j, wantLookup := range tt.wantLookups[i] {
						if len(wantLookup) != 3 {
							t.Fatalf("test setup error: wantLookup for request %d lookup %d contains %d IPs, expected 3",
								i, j, len(wantLookup))
						}
						pip, tip, wantDip := wantLookup[0], wantLookup[1], wantLookup[2]
						gotDip := c.connector.transitIPTarget(pip, tip)
						if gotDip != wantDip {
							t.Errorf("wrong result on lookup[%d][%d] ([%v], [%v]): got [%v] expected [%v]",
								i, j, pip, tip, gotDip, wantDip)
						}
					}
				}
			}
		})
	}
}

func TestReserveIPs(t *testing.T) {
	c := newConn25(logger.Discard)
	c.client.magicIPPool = newIPPool(mustIPSetFromPrefix("100.64.0.0/24"))
	c.client.transitIPPool = newIPPool(mustIPSetFromPrefix("169.254.0.0/24"))
	mbd := map[dnsname.FQDN][]string{}
	mbd["example.com."] = []string{"a"}
	c.client.config.appNamesByDomain = mbd

	dst := netip.MustParseAddr("0.0.0.1")
	addrs, err := c.client.reserveAddresses("example.com.", dst)
	if err != nil {
		t.Fatal(err)
	}

	wantDst := netip.MustParseAddr("0.0.0.1")         // same as dst we pass in
	wantMagic := netip.MustParseAddr("100.64.0.0")    // first from magic pool
	wantTransit := netip.MustParseAddr("169.254.0.0") // first from transit pool
	wantApp := "a"                                    // the app name related to example.com.
	wantDomain := must.Get(dnsname.ToFQDN("example.com."))

	if wantDst != addrs.dst {
		t.Errorf("want %v, got %v", wantDst, addrs.dst)
	}
	if wantMagic != addrs.magic {
		t.Errorf("want %v, got %v", wantMagic, addrs.magic)
	}
	if wantTransit != addrs.transit {
		t.Errorf("want %v, got %v", wantTransit, addrs.transit)
	}
	if wantApp != addrs.app {
		t.Errorf("want %s, got %s", wantApp, addrs.app)
	}
	if wantDomain != addrs.domain {
		t.Errorf("want %s, got %s", wantDomain, addrs.domain)
	}
}

func TestReconfig(t *testing.T) {
	rawCfg := `{"name":"app1","connectors":["tag:woo"],"domains":["example.com"]}`
	capMap := tailcfg.NodeCapMap{
		tailcfg.NodeCapability(AppConnectorsExperimentalAttrName): []tailcfg.RawMessage{
			tailcfg.RawMessage(rawCfg),
		},
	}

	c := newConn25(logger.Discard)
	sn := (&tailcfg.Node{
		CapMap: capMap,
	}).View()

	err := c.reconfig(sn)
	if err != nil {
		t.Fatal(err)
	}

	if len(c.client.config.apps) != 1 || c.client.config.apps[0].Name != "app1" {
		t.Fatalf("want apps to have one entry 'app1', got %v", c.client.config.apps)
	}
}

func TestConfigReconfig(t *testing.T) {
	for _, tt := range []struct {
		name                  string
		rawCfg                string
		cfg                   []appctype.Conn25Attr
		tags                  []string
		wantErr               bool
		wantAppsByDomain      map[dnsname.FQDN][]string
		wantSelfRoutedDomains set.Set[dnsname.FQDN]
	}{
		{
			name:    "bad-config",
			rawCfg:  `bad`,
			wantErr: true,
		},
		{
			name: "simple",
			cfg: []appctype.Conn25Attr{
				{Name: "one", Domains: []string{"a.example.com"}, Connectors: []string{"tag:one"}},
				{Name: "two", Domains: []string{"b.example.com"}, Connectors: []string{"tag:two"}},
			},
			tags: []string{"tag:one"},
			wantAppsByDomain: map[dnsname.FQDN][]string{
				"a.example.com.": {"one"},
				"b.example.com.": {"two"},
			},
			wantSelfRoutedDomains: set.SetOf([]dnsname.FQDN{"a.example.com."}),
		},
		{
			name: "more-complex",
			cfg: []appctype.Conn25Attr{
				{Name: "one", Domains: []string{"1.a.example.com", "1.b.example.com"}, Connectors: []string{"tag:one", "tag:onea"}},
				{Name: "two", Domains: []string{"2.b.example.com", "2.c.example.com"}, Connectors: []string{"tag:two", "tag:twoa"}},
				{Name: "three", Domains: []string{"1.b.example.com", "1.c.example.com"}, Connectors: []string{}},
				{Name: "four", Domains: []string{"4.b.example.com", "4.d.example.com"}, Connectors: []string{"tag:four"}},
			},
			tags: []string{"tag:onea", "tag:four", "tag:unrelated"},
			wantAppsByDomain: map[dnsname.FQDN][]string{
				"1.a.example.com.": {"one"},
				"1.b.example.com.": {"one", "three"},
				"1.c.example.com.": {"three"},
				"2.b.example.com.": {"two"},
				"2.c.example.com.": {"two"},
				"4.b.example.com.": {"four"},
				"4.d.example.com.": {"four"},
			},
			wantSelfRoutedDomains: set.SetOf([]dnsname.FQDN{"1.a.example.com.", "1.b.example.com.", "4.b.example.com.", "4.d.example.com."}),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := []tailcfg.RawMessage{tailcfg.RawMessage(tt.rawCfg)}
			if tt.cfg != nil {
				cfg = []tailcfg.RawMessage{}
				for _, attr := range tt.cfg {
					bs, err := json.Marshal(attr)
					if err != nil {
						t.Fatalf("unexpected error in test setup: %v", err)
					}
					cfg = append(cfg, tailcfg.RawMessage(bs))
				}
			}
			capMap := tailcfg.NodeCapMap{
				tailcfg.NodeCapability(AppConnectorsExperimentalAttrName): cfg,
			}
			sn := (&tailcfg.Node{
				CapMap: capMap,
				Tags:   tt.tags,
			}).View()
			c, err := configFromNodeView(sn)
			if (err != nil) != tt.wantErr {
				t.Fatalf("wantErr: %t, err: %v", tt.wantErr, err)
			}
			if diff := cmp.Diff(tt.wantAppsByDomain, c.appNamesByDomain); diff != "" {
				t.Errorf("appsByDomain diff (-want, +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantSelfRoutedDomains, c.selfRoutedDomains); diff != "" {
				t.Errorf("selfRoutedDomains diff (-want, +got):\n%s", diff)
			}
		})
	}
}

func makeSelfNode(t *testing.T, attr appctype.Conn25Attr, tags []string) tailcfg.NodeView {
	t.Helper()
	bs, err := json.Marshal(attr)
	if err != nil {
		t.Fatalf("unexpected error in test setup: %v", err)
	}
	cfg := []tailcfg.RawMessage{tailcfg.RawMessage(bs)}
	capMap := tailcfg.NodeCapMap{
		tailcfg.NodeCapability(AppConnectorsExperimentalAttrName): cfg,
	}
	return (&tailcfg.Node{
		CapMap: capMap,
		Tags:   tags,
	}).View()
}

func rangeFrom(from, to string) netipx.IPRange {
	return netipx.IPRangeFrom(
		netip.MustParseAddr("100.64.0."+from),
		netip.MustParseAddr("100.64.0."+to),
	)
}

func TestMapDNSResponse(t *testing.T) {
	makeDNSResponse := func(domain string, addrs []dnsmessage.AResource) []byte {
		b := dnsmessage.NewBuilder(nil,
			dnsmessage.Header{
				ID:            1,
				Response:      true,
				Authoritative: true,
				RCode:         dnsmessage.RCodeSuccess,
			})
		b.EnableCompression()

		if err := b.StartQuestions(); err != nil {
			t.Fatal(err)
		}

		if err := b.Question(dnsmessage.Question{
			Name:  dnsmessage.MustNewName(domain),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}); err != nil {
			t.Fatal(err)
		}

		if err := b.StartAnswers(); err != nil {
			t.Fatal(err)
		}

		for _, addr := range addrs {
			b.AResource(
				dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName(domain),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				addr,
			)
		}

		outbs, err := b.Finish()
		if err != nil {
			t.Fatal(err)
		}
		return outbs
	}

	for _, tt := range []struct {
		name          string
		domain        string
		addrs         []dnsmessage.AResource
		wantByMagicIP map[netip.Addr]addrs
	}{
		{
			name:   "one-ip-matches",
			domain: "example.com.",
			addrs:  []dnsmessage.AResource{{A: [4]byte{1, 0, 0, 0}}},
			// these are 'expected' because they are the beginning of the provided pools
			wantByMagicIP: map[netip.Addr]addrs{
				netip.MustParseAddr("100.64.0.0"): {
					domain:  "example.com.",
					dst:     netip.MustParseAddr("1.0.0.0"),
					magic:   netip.MustParseAddr("100.64.0.0"),
					transit: netip.MustParseAddr("100.64.0.40"),
					app:     "app1",
				},
			},
		},
		{
			name:   "multiple-ip-matches",
			domain: "example.com.",
			addrs: []dnsmessage.AResource{
				{A: [4]byte{1, 0, 0, 0}},
				{A: [4]byte{2, 0, 0, 0}},
			},
			wantByMagicIP: map[netip.Addr]addrs{
				netip.MustParseAddr("100.64.0.0"): {
					domain:  "example.com.",
					dst:     netip.MustParseAddr("1.0.0.0"),
					magic:   netip.MustParseAddr("100.64.0.0"),
					transit: netip.MustParseAddr("100.64.0.40"),
					app:     "app1",
				},
				netip.MustParseAddr("100.64.0.1"): {
					domain:  "example.com.",
					dst:     netip.MustParseAddr("2.0.0.0"),
					magic:   netip.MustParseAddr("100.64.0.1"),
					transit: netip.MustParseAddr("100.64.0.41"),
					app:     "app1",
				},
			},
		},
		{
			name:   "no-domain-match",
			domain: "x.example.com.",
			addrs: []dnsmessage.AResource{
				{A: [4]byte{1, 0, 0, 0}},
				{A: [4]byte{2, 0, 0, 0}},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dnsResp := makeDNSResponse(tt.domain, tt.addrs)
			sn := makeSelfNode(t, appctype.Conn25Attr{
				Name:          "app1",
				Connectors:    []string{"tag:woo"},
				Domains:       []string{"example.com"},
				MagicIPPool:   []netipx.IPRange{rangeFrom("0", "10"), rangeFrom("20", "30")},
				TransitIPPool: []netipx.IPRange{rangeFrom("40", "50")},
			}, []string{})
			c := newConn25(logger.Discard)
			c.reconfig(sn)

			bs := c.mapDNSResponse(dnsResp)
			if !reflect.DeepEqual(dnsResp, bs) {
				t.Fatal("shouldn't be changing the bytes (yet)")
			}
			if diff := cmp.Diff(tt.wantByMagicIP, c.client.assignments.byMagicIP, cmpopts.EquateComparable(addrs{}, netip.Addr{})); diff != "" {
				t.Errorf("byMagicIP diff (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestReserveAddressesDeduplicated(t *testing.T) {
	c := newConn25(logger.Discard)
	c.client.magicIPPool = newIPPool(mustIPSetFromPrefix("100.64.0.0/24"))
	c.client.transitIPPool = newIPPool(mustIPSetFromPrefix("169.254.0.0/24"))
	c.client.config.appNamesByDomain = map[dnsname.FQDN][]string{"example.com.": {"a"}}

	dst := netip.MustParseAddr("0.0.0.1")
	first, err := c.client.reserveAddresses("example.com.", dst)
	if err != nil {
		t.Fatal(err)
	}

	second, err := c.client.reserveAddresses("example.com.", dst)
	if err != nil {
		t.Fatal(err)
	}

	if first != second {
		t.Errorf("expected same addrs on repeated call, got first=%v second=%v", first, second)
	}
	if got := len(c.client.assignments.byMagicIP); got != 1 {
		t.Errorf("want 1 entry in byMagicIP, got %d", got)
	}
	if got := len(c.client.assignments.byDomainDst); got != 1 {
		t.Errorf("want 1 entry in byDomainDst, got %d", got)
	}
}

type testNodeBackend struct {
	ipnext.NodeBackend
	peers      []tailcfg.NodeView
	peerAPIURL string // should be per peer but there's only one peer in our test so this is ok for now
}

func (nb *testNodeBackend) AppendMatchingPeers(base []tailcfg.NodeView, pred func(tailcfg.NodeView) bool) []tailcfg.NodeView {
	for _, p := range nb.peers {
		if pred(p) {
			base = append(base, p)
		}
	}
	return base
}

func (nb *testNodeBackend) PeerHasPeerAPI(p tailcfg.NodeView) bool {
	return true
}

func (nb *testNodeBackend) PeerAPIBase(p tailcfg.NodeView) string {
	return nb.peerAPIURL
}

type testHost struct {
	ipnext.Host
	nb    ipnext.NodeBackend
	hooks ipnext.Hooks
}

func (h *testHost) NodeBackend() ipnext.NodeBackend { return h.nb }
func (h *testHost) Hooks() *ipnext.Hooks            { return &h.hooks }

type testSafeBackend struct {
	ipnext.SafeBackend
	sys *tsd.System
}

func (b *testSafeBackend) Sys() *tsd.System { return b.sys }

// TestEnqueueAddress tests that after enqueueAddress has been called a
// peerapi request is made to a peer.
func TestEnqueueAddress(t *testing.T) {
	// make a fake peer to test against
	received := make(chan ConnectorTransitIPRequest, 1)
	peersAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/connector/transit-ip" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		var req ConnectorTransitIPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		received <- req
		resp := ConnectorTransitIPResponse{
			TransitIPs: []TransitIPResponse{{Code: OK}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer peersAPI.Close()

	connectorPeer := (&tailcfg.Node{
		ID:       tailcfg.NodeID(1),
		Tags:     []string{"tag:woo"},
		Hostinfo: (&tailcfg.Hostinfo{AppConnector: opt.NewBool(true)}).View(),
	}).View()

	// make extension to test
	sys := &tsd.System{}
	sys.Dialer.Set(&tsdial.Dialer{Logf: logger.Discard})

	ext := &extension{
		conn25:  newConn25(logger.Discard),
		backend: &testSafeBackend{sys: sys},
	}
	if err := ext.Init(&testHost{
		nb: &testNodeBackend{
			peers:      []tailcfg.NodeView{connectorPeer},
			peerAPIURL: peersAPI.URL,
		},
	}); err != nil {
		t.Fatal(err)
	}
	defer ext.Shutdown()

	sn := makeSelfNode(t, appctype.Conn25Attr{
		Name:       "app1",
		Connectors: []string{"tag:woo"},
		Domains:    []string{"example.com"},
	}, []string{})
	err := ext.conn25.reconfig(sn)
	if err != nil {
		t.Fatal(err)
	}

	as := addrs{
		dst:     netip.MustParseAddr("1.2.3.4"),
		magic:   netip.MustParseAddr("100.64.0.0"),
		transit: netip.MustParseAddr("169.254.0.1"),
		domain:  "example.com.",
		app:     "app1",
	}
	ext.conn25.client.enqueueAddressAssignment(as)

	select {
	case got := <-received:
		if len(got.TransitIPs) != 1 {
			t.Fatalf("want 1 TransitIP in request, got %d", len(got.TransitIPs))
		}
		tip := got.TransitIPs[0]
		if tip.TransitIP != as.transit {
			t.Errorf("TransitIP: got %v, want %v", tip.TransitIP, as.transit)
		}
		if tip.DestinationIP != as.dst {
			t.Errorf("DestinationIP: got %v, want %v", tip.DestinationIP, as.dst)
		}
		if tip.App != as.app {
			t.Errorf("App: got %q, want %q", tip.App, as.app)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for connector to receive request")
	}
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go4.org/mem"
	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/appctype"
	"tailscale.com/types/key"
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
						aa, _ := c.connector.lookupBySrcIPAndTransitIP(pip, tip)
						gotDip := aa.addr
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

func makeSelfNode(t *testing.T, attrs []appctype.Conn25Attr, tags []string) tailcfg.NodeView {
	t.Helper()
	cfg := make([]tailcfg.RawMessage, 0, len(attrs))
	for i, attr := range attrs {
		bs, err := json.Marshal(attr)
		if err != nil {
			t.Fatalf("unexpected error in test setup at index %d: %v", i, err)
		}
		cfg = append(cfg, tailcfg.RawMessage(bs))
	}
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

func makeDNSResponse(t *testing.T, domain string, addrs []*dnsmessage.AResource) []byte {
	t.Helper()
	name := dnsmessage.MustNewName(domain)
	questions := []dnsmessage.Question{
		{
			Name:  name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		},
	}
	var answers []dnsmessage.Resource
	for _, addr := range addrs {
		ans := dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
			Body: addr,
		}
		answers = append(answers, ans)
	}
	additional := []dnsmessage.Resource{
		{
			Header: dnsmessage.ResourceHeader{
				Name:  name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
			Body: &dnsmessage.AResource{A: [4]byte{9, 9, 9, 9}},
		},
	}
	return makeDNSResponseForSections(t, questions, answers, additional)
}

func makeV6DNSResponse(t *testing.T, domain string, addrs []*dnsmessage.AAAAResource) []byte {
	t.Helper()
	name := dnsmessage.MustNewName(domain)
	questions := []dnsmessage.Question{
		{
			Name:  name,
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
		},
	}
	var answers []dnsmessage.Resource
	for _, addr := range addrs {
		ans := dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  name,
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			},
			Body: addr,
		}
		answers = append(answers, ans)
	}
	return makeDNSResponseForSections(t, questions, answers, nil)
}

func makeDNSResponseForSections(t *testing.T, questions []dnsmessage.Question, answers []dnsmessage.Resource, additional []dnsmessage.Resource) []byte {
	t.Helper()
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

	for _, q := range questions {
		if err := b.Question(q); err != nil {
			t.Fatal(err)
		}
	}

	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}

	for _, ans := range answers {
		switch ans.Header.Type {
		case dnsmessage.TypeA:
			body, ok := (ans.Body).(*dnsmessage.AResource)
			if !ok {
				t.Fatalf("unexpected answer type, update test")
			}
			b.AResource(ans.Header, *body)
		case dnsmessage.TypeAAAA:
			body, ok := (ans.Body).(*dnsmessage.AAAAResource)
			if !ok {
				t.Fatalf("unexpected answer type, update test")
			}
			b.AAAAResource(ans.Header, *body)
		default:
			t.Fatalf("unhandled answer type, update test: %v", ans.Header.Type)
		}
	}

	if err := b.StartAdditionals(); err != nil {
		t.Fatal(err)
	}
	for _, add := range additional {
		body, ok := (add.Body).(*dnsmessage.AResource)
		if !ok {
			t.Fatalf("unexpected additional type, update test")
		}
		b.AResource(add.Header, *body)
	}

	outbs, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return outbs
}

func TestMapDNSResponseAssignsAddrs(t *testing.T) {
	for _, tt := range []struct {
		name          string
		domain        string
		addrs         []*dnsmessage.AResource
		wantByMagicIP map[netip.Addr]addrs
	}{
		{
			name:   "one-ip-matches",
			domain: "example.com.",
			addrs:  []*dnsmessage.AResource{{A: [4]byte{1, 0, 0, 0}}},
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
			addrs: []*dnsmessage.AResource{
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
			addrs: []*dnsmessage.AResource{
				{A: [4]byte{1, 0, 0, 0}},
				{A: [4]byte{2, 0, 0, 0}},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dnsResp := makeDNSResponse(t, tt.domain, tt.addrs)
			sn := makeSelfNode(t, []appctype.Conn25Attr{{
				Name:          "app1",
				Connectors:    []string{"tag:woo"},
				Domains:       []string{"example.com"},
				MagicIPPool:   []netipx.IPRange{rangeFrom("0", "10"), rangeFrom("20", "30")},
				TransitIPPool: []netipx.IPRange{rangeFrom("40", "50")},
			}}, []string{})
			c := newConn25(logger.Discard)
			c.reconfig(sn)

			c.mapDNSResponse(dnsResp)
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
	nb                ipnext.NodeBackend
	hooks             ipnext.Hooks
	authReconfigAsync func()
}

func (h *testHost) NodeBackend() ipnext.NodeBackend { return h.nb }
func (h *testHost) Hooks() *ipnext.Hooks            { return &h.hooks }
func (h *testHost) AuthReconfigAsync()              { h.authReconfigAsync() }

type testSafeBackend struct {
	ipnext.SafeBackend
	sys *tsd.System
}

func (b *testSafeBackend) Sys() *tsd.System { return b.sys }

// TestAddressAssignmentIsHandled tests that after enqueueAddress has been called
// we handle the assignment asynchronously by:
//   - making a peerapi request to a peer.
//   - calling AuthReconfigAsync on the host.
func TestAddressAssignmentIsHandled(t *testing.T) {
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
		Key:      key.NodePublicFromRaw32(mem.B([]byte{0: 0xff, 1: 0xff, 31: 0x01})),
	}).View()

	// make extension to test
	sys := &tsd.System{}
	sys.Dialer.Set(&tsdial.Dialer{Logf: logger.Discard})

	ext := &extension{
		conn25:  newConn25(logger.Discard),
		backend: &testSafeBackend{sys: sys},
	}
	authReconfigAsyncCalled := make(chan struct{}, 1)
	if err := ext.Init(&testHost{
		nb: &testNodeBackend{
			peers:      []tailcfg.NodeView{connectorPeer},
			peerAPIURL: peersAPI.URL,
		},
		authReconfigAsync: func() {
			authReconfigAsyncCalled <- struct{}{}
		},
	}); err != nil {
		t.Fatal(err)
	}
	defer ext.Shutdown()

	sn := makeSelfNode(t, []appctype.Conn25Attr{{
		Name:       "app1",
		Connectors: []string{"tag:woo"},
		Domains:    []string{"example.com"},
	}}, []string{})
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
	if err := ext.conn25.client.assignments.insert(as); err != nil {
		t.Fatalf("error inserting address assignments: %v", err)
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
	select {
	case <-authReconfigAsyncCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for AuthReconfigAsync to be called")
	}
}

func parseResponse(t *testing.T, buf []byte) ([]dnsmessage.Resource, []dnsmessage.Resource) {
	t.Helper()
	var p dnsmessage.Parser
	header, err := p.Start(buf)
	if err != nil {
		t.Fatalf("parsing DNS response: %v", err)
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("RCode want: %v, got: %v", dnsmessage.RCodeSuccess, header.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("skipping questions: %v", err)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatalf("reading answers: %v", err)
	}
	if err := p.SkipAllAuthorities(); err != nil {
		t.Fatalf("skipping questions: %v", err)
	}
	additionals, err := p.AllAdditionals()
	if err != nil {
		t.Fatalf("reading additionals: %v", err)
	}
	return answers, additionals
}

func TestMapDNSResponseRewritesResponses(t *testing.T) {
	configuredDomain := "example.com"
	domainName := configuredDomain + "."
	dnsMessageName := dnsmessage.MustNewName(domainName)
	sn := makeSelfNode(t, []appctype.Conn25Attr{{
		Name:          "app1",
		Connectors:    []string{"tag:connector"},
		Domains:       []string{configuredDomain},
		MagicIPPool:   []netipx.IPRange{rangeFrom("0", "10")},
		TransitIPPool: []netipx.IPRange{rangeFrom("40", "50")},
	}}, []string{})

	compareToRecords := func(t *testing.T, resources []dnsmessage.Resource, want []netip.Addr) {
		t.Helper()
		var got []netip.Addr
		for _, r := range resources {
			if b, ok := r.Body.(*dnsmessage.AResource); ok {
				got = append(got, netip.AddrFrom4(b.A))
			} else if b, ok := r.Body.(*dnsmessage.AAAAResource); ok {
				got = append(got, netip.AddrFrom16(b.AAAA))
			}
		}
		if diff := cmp.Diff(want, got, cmpopts.EquateComparable(netip.Addr{})); diff != "" {
			t.Fatalf("A/AAAA records mismatch (-want +got):\n%s", diff)
		}
	}

	assertParsesToAnswers := func(want []netip.Addr) func(t *testing.T, bs []byte) {
		return func(t *testing.T, bs []byte) {
			t.Helper()
			answers, _ := parseResponse(t, bs)
			compareToRecords(t, answers, want)
		}
	}

	assertParsesToAdditionals := func(want []netip.Addr) func(t *testing.T, bs []byte) {
		return func(t *testing.T, bs []byte) {
			t.Helper()
			_, additionals := parseResponse(t, bs)
			compareToRecords(t, additionals, want)
		}
	}

	assertBytes := func(want []byte) func(t *testing.T, bs []byte) {
		return func(t *testing.T, bs []byte) {
			t.Helper()
			if diff := cmp.Diff(want, bs); diff != "" {
				t.Fatalf("bytes mismatch (-want +got):\n%s", diff)
			}
		}
	}
	assertServFail := func(t *testing.T, bs []byte) {
		var p dnsmessage.Parser
		header, err := p.Start(bs)
		if err != nil {
			t.Fatalf("parsing DNS response: %v", err)
		}
		if header.RCode != dnsmessage.RCodeServerFailure {
			t.Fatalf("RCode want: %v, got: %v", dnsmessage.RCodeServerFailure, header.RCode)
		}
	}

	ipv6ResponseUnhandledDomain := makeV6DNSResponse(t, "tailscale.com.", []*dnsmessage.AAAAResource{
		{AAAA: netip.MustParseAddr("2606:4700::6812:1a78").As16()},
		{AAAA: netip.MustParseAddr("2606:4700::6812:1b78").As16()},
	})

	ipv4ResponseUnhandledDomain := makeDNSResponse(t, "tailscale.com.", []*dnsmessage.AResource{
		{A: netip.MustParseAddr("1.2.3.4").As4()},
		{A: netip.MustParseAddr("5.6.7.8").As4()},
	})

	nonINETQuestionResp := makeDNSResponseForSections(t, []dnsmessage.Question{
		{
			Name:  dnsMessageName,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassCHAOS,
		},
	}, nil, nil)

	for _, tt := range []struct {
		name     string
		toMap    []byte
		assertFx func(*testing.T, []byte)
	}{
		{
			name:     "unparseable",
			toMap:    []byte{1, 2, 3, 4},
			assertFx: assertBytes([]byte{1, 2, 3, 4}),
		},
		{
			name: "maps-multi-typea-answers",
			toMap: makeDNSResponse(t, domainName, []*dnsmessage.AResource{
				{A: netip.MustParseAddr("1.2.3.4").As4()},
				{A: netip.MustParseAddr("5.6.7.8").As4()},
			}),
			assertFx: assertParsesToAnswers(
				[]netip.Addr{
					netip.MustParseAddr("100.64.0.0"),
					netip.MustParseAddr("100.64.0.1"),
				},
			),
		},
		{
			name: "ipv6-no-answers",
			toMap: makeV6DNSResponse(t, domainName, []*dnsmessage.AAAAResource{
				{AAAA: netip.MustParseAddr("2606:4700::6812:1a78").As16()},
				{AAAA: netip.MustParseAddr("2606:4700::6812:1b78").As16()},
			}),
			assertFx: assertParsesToAnswers(nil),
		},
		{
			name:     "not-our-domain",
			toMap:    ipv4ResponseUnhandledDomain,
			assertFx: assertBytes(ipv4ResponseUnhandledDomain),
		},
		{
			name:     "ipv6-not-our-domain",
			toMap:    ipv6ResponseUnhandledDomain,
			assertFx: assertBytes(ipv6ResponseUnhandledDomain),
		},
		{
			name: "case-insensitive",
			toMap: makeDNSResponse(t, "eXample.com.", []*dnsmessage.AResource{
				{A: netip.MustParseAddr("1.2.3.4").As4()},
				{A: netip.MustParseAddr("5.6.7.8").As4()},
			}),
			assertFx: assertParsesToAnswers(
				[]netip.Addr{
					netip.MustParseAddr("100.64.0.0"),
					netip.MustParseAddr("100.64.0.1"),
				},
			),
		},
		{
			name: "unhandled-keeps-additional-section",
			toMap: makeDNSResponse(t, "tailscale.com.", []*dnsmessage.AResource{
				{A: netip.MustParseAddr("1.2.3.4").As4()},
				{A: netip.MustParseAddr("5.6.7.8").As4()},
			}),
			assertFx: assertParsesToAdditionals(
				// additionals are added in makeDNSResponse
				[]netip.Addr{
					netip.MustParseAddr("9.9.9.9"),
				},
			),
		},
		{
			name: "handled-strips-additional-section",
			toMap: makeDNSResponse(t, domainName, []*dnsmessage.AResource{
				{A: netip.MustParseAddr("1.2.3.4").As4()},
				{A: netip.MustParseAddr("5.6.7.8").As4()},
			}),
			assertFx: assertParsesToAdditionals(nil),
		},
		{
			name: "servfail-when-we-should-handle-but-cant",
			// produced by
			// makeDNSResponse(t, domainName, []*dnsmessage.AResource{{A: netip.MustParseAddr("1.2.3.4").As4()}})
			// and then taking 17 bytes off the end. So that the parsing of it breaks after we have decided we should handle it.
			// Frozen like this so that it doesn't depend on the implementation of dnsmessage.
			toMap:    []byte{0, 1, 132, 0, 0, 1, 0, 1, 0, 0, 0, 1, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 1, 2, 3},
			assertFx: assertServFail,
		},
		{
			name:     "not-inet-question",
			toMap:    nonINETQuestionResp,
			assertFx: assertBytes(nonINETQuestionResp),
		},
		{
			name: "not-inet-answer",
			toMap: makeDNSResponseForSections(t,
				[]dnsmessage.Question{
					{
						Name:  dnsMessageName,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
				[]dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsMessageName,
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassCHAOS,
						},
						Body: &dnsmessage.AResource{A: netip.MustParseAddr("1.2.3.4").As4()},
					},
				},
				nil,
			),
			assertFx: assertParsesToAnswers(nil),
		},
		{
			name: "answer-domain-mismatch",
			toMap: makeDNSResponseForSections(t,
				[]dnsmessage.Question{
					{
						Name:  dnsMessageName,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
				[]dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("tailscale.com."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.AResource{A: netip.MustParseAddr("1.2.3.4").As4()},
					},
				},
				nil,
			),
			assertFx: assertParsesToAnswers(nil),
		},
		{
			name: "answer-type-mismatch",
			toMap: makeDNSResponseForSections(t,
				[]dnsmessage.Question{
					{
						Name:  dnsMessageName,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
				[]dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsMessageName,
							Type:  dnsmessage.TypeAAAA,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("1.2.3.4").As16()},
					},
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsMessageName,
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.AResource{A: netip.MustParseAddr("5.6.7.8").As4()},
					},
				},
				nil,
			),
			assertFx: assertParsesToAnswers([]netip.Addr{netip.MustParseAddr("100.64.0.0")}),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newConn25(logger.Discard)
			if err := c.reconfig(sn); err != nil {
				t.Fatal(err)
			}
			bs := c.mapDNSResponse(tt.toMap)
			tt.assertFx(t, bs)
		})
	}
}

func TestHandleAddressAssignmentStoresTransitIPs(t *testing.T) {
	// make a fake peer API to test against, for all peers
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
		resp := ConnectorTransitIPResponse{
			TransitIPs: []TransitIPResponse{{Code: OK}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer peersAPI.Close()

	connectorPeers := []tailcfg.NodeView{
		(&tailcfg.Node{
			ID:       tailcfg.NodeID(1),
			Tags:     []string{"tag:woo"},
			Hostinfo: (&tailcfg.Hostinfo{AppConnector: opt.NewBool(true)}).View(),
			Key:      key.NodePublicFromRaw32(mem.B([]byte{0: 0xff, 31: 0x01})),
		}).View(),
		(&tailcfg.Node{
			ID:       tailcfg.NodeID(2),
			Tags:     []string{"tag:hoo"},
			Hostinfo: (&tailcfg.Hostinfo{AppConnector: opt.NewBool(true)}).View(),
			Key:      key.NodePublicFromRaw32(mem.B([]byte{0: 0xff, 31: 0x02})),
		}).View(),
	}

	// make extension to test
	sys := &tsd.System{}
	sys.Dialer.Set(&tsdial.Dialer{Logf: logger.Discard})

	ext := &extension{
		conn25:  newConn25(logger.Discard),
		backend: &testSafeBackend{sys: sys},
	}
	authReconfigAsyncCalled := make(chan struct{}, 1)
	if err := ext.Init(&testHost{
		nb: &testNodeBackend{
			peers:      connectorPeers,
			peerAPIURL: peersAPI.URL,
		},
		authReconfigAsync: func() {
			authReconfigAsyncCalled <- struct{}{}
		},
	}); err != nil {
		t.Fatal(err)
	}
	defer ext.Shutdown()

	sn := makeSelfNode(t, []appctype.Conn25Attr{
		{
			Name:       "app1",
			Connectors: []string{"tag:woo"},
			Domains:    []string{"woo.example.com"},
		},
		{
			Name:       "app2",
			Connectors: []string{"tag:hoo"},
			Domains:    []string{"hoo.example.com"},
		},
	}, []string{})
	err := ext.conn25.reconfig(sn)
	if err != nil {
		t.Fatal(err)
	}

	type lookup struct {
		connKey     key.NodePublic
		expectedIPs []netip.Prefix
		expectedOk  bool
	}

	transitIPs := []netip.Prefix{
		netip.MustParsePrefix("169.254.0.1/32"),
		netip.MustParsePrefix("169.254.0.2/32"),
		netip.MustParsePrefix("169.254.0.3/32"),
	}
	// Each step performs an insert on the provided addrs
	// and then does the lookups.
	steps := []struct {
		name    string
		as      addrs
		lookups []lookup
	}{
		{
			name: "step-1-conn1-tip1",
			as: addrs{
				dst:     netip.MustParseAddr("1.2.3.1"),
				magic:   netip.MustParseAddr("100.64.0.1"),
				transit: transitIPs[0].Addr(),
				domain:  "woo.example.com.",
				app:     "app1",
			},
			lookups: []lookup{
				{
					connKey: connectorPeers[0].Key(),
					expectedIPs: []netip.Prefix{
						transitIPs[0],
					},
					expectedOk: true,
				},
				{
					connKey:     connectorPeers[1].Key(),
					expectedIPs: nil,
					expectedOk:  false,
				},
			},
		},
		{
			name: "step-2-conn1-tip2",
			as: addrs{
				dst:     netip.MustParseAddr("1.2.3.2"),
				magic:   netip.MustParseAddr("100.64.0.2"),
				transit: transitIPs[1].Addr(),
				domain:  "woo.example.com.",
				app:     "app1",
			},
			lookups: []lookup{
				{
					connKey: connectorPeers[0].Key(),
					expectedIPs: []netip.Prefix{
						transitIPs[0],
						transitIPs[1],
					},
					expectedOk: true,
				},
			},
		},
		{
			name: "step-3-conn2-tip1",
			as: addrs{
				dst:     netip.MustParseAddr("1.2.3.3"),
				magic:   netip.MustParseAddr("100.64.0.3"),
				transit: transitIPs[2].Addr(),
				domain:  "hoo.example.com.",
				app:     "app2",
			},
			lookups: []lookup{
				{
					connKey: connectorPeers[0].Key(),
					expectedIPs: []netip.Prefix{
						transitIPs[0],
						transitIPs[1],
					},
					expectedOk: true,
				},
				{
					connKey: connectorPeers[1].Key(),
					expectedIPs: []netip.Prefix{
						transitIPs[2],
					},
					expectedOk: true,
				},
			},
		},
	}

	for _, tt := range steps {
		t.Run(tt.name, func(t *testing.T) {
			// Add and enqueue the addrs, and then wait for the send to complete
			// (as indicated by authReconfig being called).
			if err := ext.conn25.client.assignments.insert(tt.as); err != nil {
				t.Fatalf("error inserting address assignment: %v", err)
			}
			if err := ext.conn25.client.enqueueAddressAssignment(tt.as); err != nil {
				t.Fatalf("error enqueuing address assignment: %v", err)
			}
			select {
			case <-authReconfigAsyncCalled:
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for AuthReconfigAsync to be called")
			}

			// Check that each of the lookups behaves as expected
			for i, lu := range tt.lookups {
				got, ok := ext.conn25.client.assignments.lookupTransitIPsByConnKey(lu.connKey)
				if ok != lu.expectedOk {
					t.Fatalf("unexpected ok result at index %d wanted %v, got %v", i, lu.expectedOk, ok)
				}
				slices.SortFunc(got, func(a, b netip.Prefix) int { return a.Compare(b) })
				if diff := cmp.Diff(lu.expectedIPs, got, cmpopts.EquateComparable(netip.Prefix{})); diff != "" {
					t.Fatalf("transit IPs mismatch at index %d, (-want +got):\n%s", i, diff)
				}
			}
		})
	}
}

func TestTransitIPConnMapping(t *testing.T) {
	conn25 := newConn25(t.Logf)

	as := addrs{
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
	// But doing it again should fail
	if err := conn25.client.addTransitIPForConnector(as.transit, connectorPeers[1]); err == nil {
		t.Error("adding a duplicate transitIP for a connector should fail")
	}
}

func TestClientTransitIPForMagicIP(t *testing.T) {
	sn := makeSelfNode(t, []appctype.Conn25Attr{{
		MagicIPPool: []netipx.IPRange{rangeFrom("0", "10")}, // 100.64.0.0 - 100.64.0.10
	}}, []string{})
	mappedMip := netip.MustParseAddr("100.64.0.0")
	mappedTip := netip.MustParseAddr("169.0.0.0")
	unmappedMip := netip.MustParseAddr("100.64.0.1")
	nonMip := netip.MustParseAddr("100.64.0.11")
	for _, tt := range []struct {
		name    string
		mip     netip.Addr
		wantTip netip.Addr
		wantErr error
	}{
		{
			name:    "not-a-magic-ip",
			mip:     nonMip,
			wantTip: netip.Addr{},
			wantErr: nil,
		},
		{
			name:    "unmapped-magic-ip",
			mip:     unmappedMip,
			wantTip: netip.Addr{},
			wantErr: ErrUnmappedMagicIP,
		},
		{
			name:    "mapped-magic-ip",
			mip:     mappedMip,
			wantTip: mappedTip,
			wantErr: nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newConn25(t.Logf)
			if err := c.reconfig(sn); err != nil {
				t.Fatal(err)
			}
			c.client.assignments.insert(addrs{
				magic:   mappedMip,
				transit: mappedTip,
			})
			tip, err := c.client.ClientTransitIPForMagicIP(tt.mip)
			if tip != tt.wantTip {
				t.Fatalf("checking transit ip: want %v, got %v", tt.wantTip, tip)
			}
			if err != tt.wantErr {
				t.Fatalf("checking error: want %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestConnectorRealIPForTransitIPConnection(t *testing.T) {
	sn := makeSelfNode(t, []appctype.Conn25Attr{{
		TransitIPPool: []netipx.IPRange{rangeFrom("40", "50")}, // 100.64.0.40 - 100.64.0.50
	}}, []string{})
	mappedSrc := netip.MustParseAddr("100.0.0.1")
	unmappedSrc := netip.MustParseAddr("100.0.0.2")
	mappedTip := netip.MustParseAddr("100.64.0.41")
	unmappedTip := netip.MustParseAddr("100.64.0.42")
	nonTip := netip.MustParseAddr("100.0.0.3")
	mappedMip := netip.MustParseAddr("100.64.0.1")
	for _, tt := range []struct {
		name    string
		src     netip.Addr
		tip     netip.Addr
		wantMip netip.Addr
		wantErr error
	}{
		{
			name:    "not-a-transit-ip-unmapped-src",
			src:     unmappedSrc,
			tip:     nonTip,
			wantMip: netip.Addr{},
			wantErr: nil,
		},
		{
			name:    "not-a-transit-ip-mapped-src",
			src:     mappedSrc,
			tip:     nonTip,
			wantMip: netip.Addr{},
			wantErr: nil,
		},
		{
			name:    "unmapped-src-transit-ip",
			src:     unmappedSrc,
			tip:     unmappedTip,
			wantMip: netip.Addr{},
			wantErr: ErrUnmappedSrcAndTransitIP,
		},
		{
			name:    "unmapped-tip-transit-ip",
			src:     mappedSrc,
			tip:     unmappedTip,
			wantMip: netip.Addr{},
			wantErr: ErrUnmappedSrcAndTransitIP,
		},
		{
			name:    "mapped-src-and-transit-ip",
			src:     mappedSrc,
			tip:     mappedTip,
			wantMip: mappedMip,
			wantErr: nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newConn25(t.Logf)
			if err := c.reconfig(sn); err != nil {
				t.Fatal(err)
			}
			c.connector.transitIPs = map[netip.Addr]map[netip.Addr]appAddr{}
			c.connector.transitIPs[mappedSrc] = map[netip.Addr]appAddr{}
			c.connector.transitIPs[mappedSrc][mappedTip] = appAddr{addr: mappedMip}
			mip, err := c.connector.ConnectorRealIPForTransitIPConnection(tt.src, tt.tip)
			if mip != tt.wantMip {
				t.Fatalf("checking magic ip: want %v, got %v", tt.wantMip, mip)
			}
			if err != tt.wantErr {
				t.Fatalf("checking error: want %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestIsKnownTransitIP(t *testing.T) {
	knownTip := netip.MustParseAddr("100.64.0.41")
	unknownTip := netip.MustParseAddr("100.64.0.42")

	c := newConn25(t.Logf)
	c.client.assignments.insert(addrs{
		transit: knownTip,
	})

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
	c.client.assignments.insert(addrs{
		transit: knownTip,
	})

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

func TestConnectorPacketFilterAllow(t *testing.T) {
	knownTip := netip.MustParseAddr("100.64.0.41")
	knownSrc := netip.MustParseAddr("100.64.0.1")
	unknownTip := netip.MustParseAddr("100.64.0.42")
	unknownSrc := netip.MustParseAddr("100.64.0.42")

	c := newConn25(t.Logf)
	c.connector.transitIPs = map[netip.Addr]map[netip.Addr]appAddr{}
	c.connector.transitIPs[knownSrc] = map[netip.Addr]appAddr{}
	c.connector.transitIPs[knownSrc][knownTip] = appAddr{}

	if allow, _ := c.connector.packetFilterAllow(packet.Parsed{
		Src: netip.AddrPortFrom(knownSrc, 1234),
		Dst: netip.AddrPortFrom(knownTip, 1234),
	}); !allow {
		t.Fatal("knownTip: should have been allowed")
	}

	if allow, _ := c.connector.packetFilterAllow(packet.Parsed{
		Src: netip.AddrPortFrom(unknownSrc, 1234),
		Dst: netip.AddrPortFrom(knownTip, 1234),
	}); allow {
		t.Fatal("unknownSrc: should not have been allowed")
	}
	if allow, _ := c.connector.packetFilterAllow(packet.Parsed{
		Src: netip.AddrPortFrom(knownSrc, 1234),
		Dst: netip.AddrPortFrom(unknownTip, 1234),
	}); allow {
		t.Fatal("unknownTip: should not have been allowed")
	}
}

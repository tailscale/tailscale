// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
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

// TestHandleConnectorTransitIPRequestZeroLength tests that if sent a
// ConnectorTransitIPRequest with 0 TransitIPRequests, we respond with a
// ConnectorTransitIPResponse with 0 TransitIPResponses.
func TestHandleConnectorTransitIPRequestZeroLength(t *testing.T) {
	c := newConn25(logger.Discard)
	req := ConnectorTransitIPRequest{}
	nid := tailcfg.NodeID(1)

	resp := c.handleConnectorTransitIPRequest(nid, req)
	if len(resp.TransitIPs) != 0 {
		t.Fatalf("n TransitIPs in response: %d, want 0", len(resp.TransitIPs))
	}
}

// TestHandleConnectorTransitIPRequestStoresAddr tests that if sent a
// request with a transit addr and a destination addr we store that mapping
// and can retrieve it. If sent another req with a different dst for that transit addr
// we store that instead.
func TestHandleConnectorTransitIPRequestStoresAddr(t *testing.T) {
	c := newConn25(logger.Discard)
	nid := tailcfg.NodeID(1)
	tip := netip.MustParseAddr("0.0.0.1")
	dip := netip.MustParseAddr("1.2.3.4")
	dip2 := netip.MustParseAddr("1.2.3.5")
	mr := func(t, d netip.Addr) ConnectorTransitIPRequest {
		return ConnectorTransitIPRequest{
			TransitIPs: []TransitIPRequest{
				{TransitIP: t, DestinationIP: d},
			},
		}
	}

	resp := c.handleConnectorTransitIPRequest(nid, mr(tip, dip))
	if len(resp.TransitIPs) != 1 {
		t.Fatalf("n TransitIPs in response: %d, want 1", len(resp.TransitIPs))
	}
	got := resp.TransitIPs[0].Code
	if got != TransitIPResponseCode(0) {
		t.Fatalf("TransitIP Code: %d, want 0", got)
	}
	gotAddr := c.connector.transitIPTarget(nid, tip)
	if gotAddr != dip {
		t.Fatalf("Connector stored destination for tip: %v, want %v", gotAddr, dip)
	}

	// mapping can be overwritten
	resp2 := c.handleConnectorTransitIPRequest(nid, mr(tip, dip2))
	if len(resp2.TransitIPs) != 1 {
		t.Fatalf("n TransitIPs in response: %d, want 1", len(resp2.TransitIPs))
	}
	got2 := resp.TransitIPs[0].Code
	if got2 != TransitIPResponseCode(0) {
		t.Fatalf("TransitIP Code: %d, want 0", got2)
	}
	gotAddr2 := c.connector.transitIPTarget(nid, tip)
	if gotAddr2 != dip2 {
		t.Fatalf("Connector stored destination for tip: %v, want %v", gotAddr, dip2)
	}
}

// TestHandleConnectorTransitIPRequestMultipleTIP tests that we can
// get a req with multiple mappings and we store them all. Including
// multiple transit addrs for the same destination.
func TestHandleConnectorTransitIPRequestMultipleTIP(t *testing.T) {
	c := newConn25(logger.Discard)
	nid := tailcfg.NodeID(1)
	tip := netip.MustParseAddr("0.0.0.1")
	tip2 := netip.MustParseAddr("0.0.0.2")
	tip3 := netip.MustParseAddr("0.0.0.3")
	dip := netip.MustParseAddr("1.2.3.4")
	dip2 := netip.MustParseAddr("1.2.3.5")
	req := ConnectorTransitIPRequest{
		TransitIPs: []TransitIPRequest{
			{TransitIP: tip, DestinationIP: dip},
			{TransitIP: tip2, DestinationIP: dip2},
			// can store same dst addr for multiple transit addrs
			{TransitIP: tip3, DestinationIP: dip},
		},
	}
	resp := c.handleConnectorTransitIPRequest(nid, req)
	if len(resp.TransitIPs) != 3 {
		t.Fatalf("n TransitIPs in response: %d, want 3", len(resp.TransitIPs))
	}

	for i := 0; i < 3; i++ {
		got := resp.TransitIPs[i].Code
		if got != TransitIPResponseCode(0) {
			t.Fatalf("i=%d TransitIP Code: %d, want 0", i, got)
		}
	}
	gotAddr1 := c.connector.transitIPTarget(nid, tip)
	if gotAddr1 != dip {
		t.Fatalf("Connector stored destination for tip(%v): %v, want %v", tip, gotAddr1, dip)
	}
	gotAddr2 := c.connector.transitIPTarget(nid, tip2)
	if gotAddr2 != dip2 {
		t.Fatalf("Connector stored destination for tip(%v): %v, want %v", tip2, gotAddr2, dip2)
	}
	gotAddr3 := c.connector.transitIPTarget(nid, tip3)
	if gotAddr3 != dip {
		t.Fatalf("Connector stored destination for tip(%v): %v, want %v", tip3, gotAddr3, dip)
	}
}

// TestHandleConnectorTransitIPRequestSameTIP tests that if we get
// a req that has more than one TransitIPRequest for the same transit addr
// only the first is stored, and the subsequent ones get an error code and
// message in the response.
func TestHandleConnectorTransitIPRequestSameTIP(t *testing.T) {
	c := newConn25(logger.Discard)
	nid := tailcfg.NodeID(1)
	tip := netip.MustParseAddr("0.0.0.1")
	tip2 := netip.MustParseAddr("0.0.0.2")
	dip := netip.MustParseAddr("1.2.3.4")
	dip2 := netip.MustParseAddr("1.2.3.5")
	dip3 := netip.MustParseAddr("1.2.3.6")
	req := ConnectorTransitIPRequest{
		TransitIPs: []TransitIPRequest{
			{TransitIP: tip, DestinationIP: dip},
			// cannot have dupe TransitIPs in one ConnectorTransitIPRequest
			{TransitIP: tip, DestinationIP: dip2},
			{TransitIP: tip2, DestinationIP: dip3},
		},
	}

	resp := c.handleConnectorTransitIPRequest(nid, req)
	if len(resp.TransitIPs) != 3 {
		t.Fatalf("n TransitIPs in response: %d, want 3", len(resp.TransitIPs))
	}

	got := resp.TransitIPs[0].Code
	if got != TransitIPResponseCode(0) {
		t.Fatalf("i=0 TransitIP Code: %d, want 0", got)
	}
	msg := resp.TransitIPs[0].Message
	if msg != "" {
		t.Fatalf("i=0 TransitIP Message: \"%s\", want \"%s\"", msg, "")
	}
	got1 := resp.TransitIPs[1].Code
	if got1 != TransitIPResponseCode(1) {
		t.Fatalf("i=1 TransitIP Code: %d, want 1", got1)
	}
	msg1 := resp.TransitIPs[1].Message
	if msg1 != dupeTransitIPMessage {
		t.Fatalf("i=1 TransitIP Message: \"%s\", want \"%s\"", msg1, dupeTransitIPMessage)
	}
	got2 := resp.TransitIPs[2].Code
	if got2 != TransitIPResponseCode(0) {
		t.Fatalf("i=2 TransitIP Code: %d, want 0", got2)
	}
	msg2 := resp.TransitIPs[2].Message
	if msg2 != "" {
		t.Fatalf("i=2 TransitIP Message: \"%s\", want \"%s\"", msg, "")
	}

	gotAddr1 := c.connector.transitIPTarget(nid, tip)
	if gotAddr1 != dip {
		t.Fatalf("Connector stored destination for tip(%v): %v, want %v", tip, gotAddr1, dip)
	}
	gotAddr2 := c.connector.transitIPTarget(nid, tip2)
	if gotAddr2 != dip3 {
		t.Fatalf("Connector stored destination for tip(%v): %v, want %v", tip2, gotAddr2, dip3)
	}
}

// TestGetDstIPUnknownTIP tests that unknown transit addresses can be looked up without problem.
func TestTransitIPTargetUnknownTIP(t *testing.T) {
	c := newConn25(logger.Discard)
	nid := tailcfg.NodeID(1)
	tip := netip.MustParseAddr("0.0.0.1")
	got := c.connector.transitIPTarget(nid, tip)
	want := netip.Addr{}
	if got != want {
		t.Fatalf("Unknown transit addr, want: %v, got %v", want, got)
	}
}

func TestSetMagicIP(t *testing.T) {
	c := newConn25(logger.Discard)
	mip := netip.MustParseAddr("0.0.0.1")
	tip := netip.MustParseAddr("0.0.0.2")
	app := "a"
	c.client.setMagicIP(mip, tip, app)
	val, ok := c.client.magicIPs[mip]
	if !ok {
		t.Fatal("expected there to be a value stored for the magic IP")
	}
	if val.addr != tip {
		t.Fatalf("want %v, got %v", tip, val.addr)
	}
	if val.app != app {
		t.Fatalf("want %s, got %s", app, val.app)
	}
}

func TestReserveIPs(t *testing.T) {
	c := newConn25(logger.Discard)
	c.client.magicIPPool = newIPPool(mustIPSetFromPrefix("100.64.0.0/24"))
	c.client.transitIPPool = newIPPool(mustIPSetFromPrefix("169.254.0.0/24"))
	mbd := map[string][]string{}
	mbd["example.com."] = []string{"a"}
	c.client.config.appsByDomain = mbd

	dst := netip.MustParseAddr("0.0.0.1")
	con, err := c.client.reserveAddresses("example.com.", dst)
	if err != nil {
		t.Fatal(err)
	}

	wantDst := netip.MustParseAddr("0.0.0.1")         // same as dst we pass in
	wantMagic := netip.MustParseAddr("100.64.0.0")    // first from magic pool
	wantTransit := netip.MustParseAddr("169.254.0.0") // first from transit pool
	wantApp := "a"                                    // the app name related to example.com.

	if wantDst != con.dst {
		t.Errorf("want %v, got %v", wantDst, con.dst)
	}
	if wantMagic != con.magic {
		t.Errorf("want %v, got %v", wantMagic, con.magic)
	}
	if wantTransit != con.transit {
		t.Errorf("want %v, got %v", wantTransit, con.transit)
	}
	if wantApp != con.app {
		t.Errorf("want %s, got %s", wantApp, con.app)
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
		wantAppsByDomain      map[string][]string
		wantSelfRoutedDomains set.Set[string]
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
			wantAppsByDomain: map[string][]string{
				"a.example.com.": {"one"},
				"b.example.com.": {"two"},
			},
			wantSelfRoutedDomains: set.SetOf([]string{"a.example.com."}),
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
			wantAppsByDomain: map[string][]string{
				"1.a.example.com.": {"one"},
				"1.b.example.com.": {"one", "three"},
				"1.c.example.com.": {"three"},
				"2.b.example.com.": {"two"},
				"2.c.example.com.": {"two"},
				"4.b.example.com.": {"four"},
				"4.d.example.com.": {"four"},
			},
			wantSelfRoutedDomains: set.SetOf([]string{"1.a.example.com.", "1.b.example.com.", "4.b.example.com.", "4.d.example.com."}),
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
			if diff := cmp.Diff(tt.wantAppsByDomain, c.appsByDomain); diff != "" {
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
		name         string
		domain       string
		addrs        []dnsmessage.AResource
		wantMagicIPs map[netip.Addr]appAddr
	}{
		{
			name:   "one-ip-matches",
			domain: "example.com.",
			addrs:  []dnsmessage.AResource{{A: [4]byte{1, 0, 0, 0}}},
			// these are 'expected' because they are the beginning of the provided pools
			wantMagicIPs: map[netip.Addr]appAddr{
				netip.MustParseAddr("100.64.0.0"): {app: "app1", addr: netip.MustParseAddr("100.64.0.40")},
			},
		},
		{
			name:   "multiple-ip-matches",
			domain: "example.com.",
			addrs: []dnsmessage.AResource{
				{A: [4]byte{1, 0, 0, 0}},
				{A: [4]byte{2, 0, 0, 0}},
			},
			wantMagicIPs: map[netip.Addr]appAddr{
				netip.MustParseAddr("100.64.0.0"): {app: "app1", addr: netip.MustParseAddr("100.64.0.40")},
				netip.MustParseAddr("100.64.0.1"): {app: "app1", addr: netip.MustParseAddr("100.64.0.41")},
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
			if diff := cmp.Diff(tt.wantMagicIPs, c.client.magicIPs, cmpopts.EquateComparable(appAddr{}, netip.Addr{})); diff != "" {
				t.Errorf("magicIPs diff (-want, +got):\n%s", diff)
			}
		})
	}
}

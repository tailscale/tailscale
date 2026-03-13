// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

	for i := range 3 {
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
			sn := makeSelfNode(t, appctype.Conn25Attr{
				Name:          "app1",
				Connectors:    []string{"tag:woo"},
				Domains:       []string{"example.com"},
				MagicIPPool:   []netipx.IPRange{rangeFrom("0", "10"), rangeFrom("20", "30")},
				TransitIPPool: []netipx.IPRange{rangeFrom("40", "50")},
			}, []string{})
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

func parseResponse(t *testing.T, buf []byte) ([]dnsmessage.Resource, []dnsmessage.Resource) {
	t.Helper()
	var p dnsmessage.Parser
	header, err := p.Start(buf)
	if err != nil {
		t.Fatalf("parsing DNS response: %v", err)
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("RCode want: %v, got: %v", dnsmessage.RCodeServerFailure, header.RCode)
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
	sn := makeSelfNode(t, appctype.Conn25Attr{
		Name:          "app1",
		Connectors:    []string{"tag:connector"},
		Domains:       []string{configuredDomain},
		MagicIPPool:   []netipx.IPRange{rangeFrom("0", "10")},
		TransitIPPool: []netipx.IPRange{rangeFrom("40", "50")},
	}, []string{})

	compareToARecords := func(t *testing.T, resources []dnsmessage.Resource, want []netip.Addr) {
		t.Helper()
		var got []netip.Addr
		for _, r := range resources {
			if b, ok := r.Body.(*dnsmessage.AResource); ok {
				got = append(got, netip.AddrFrom4(b.A))
			}
		}
		if diff := cmp.Diff(want, got, cmpopts.EquateComparable(netip.Addr{})); diff != "" {
			t.Fatalf("A records mismatch (-want +got):\n%s", diff)
		}
	}

	assertParsesToAnswers := func(want []netip.Addr) func(t *testing.T, bs []byte) {
		return func(t *testing.T, bs []byte) {
			t.Helper()
			answers, _ := parseResponse(t, bs)
			compareToARecords(t, answers, want)
		}
	}

	assertParsesToAdditionals := func(want []netip.Addr) func(t *testing.T, bs []byte) {
		return func(t *testing.T, bs []byte) {
			t.Helper()
			_, additionals := parseResponse(t, bs)
			compareToARecords(t, additionals, want)
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

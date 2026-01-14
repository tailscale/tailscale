// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
)

// TestHandleConnectorTransitIPRequestZeroLength tests that if sent a
// ConnectorTransitIPRequest with 0 TransitIPRequests, we respond with a
// ConnectorTransitIPResponse with 0 TransitIPResponses.
func TestHandleConnectorTransitIPRequestZeroLength(t *testing.T) {
	c := &Conn25{}
	req := ConnectorTransitIPRequest{}
	nid := tailcfg.NodeID(1)

	resp := c.HandleConnectorTransitIPRequest(nid, req)
	if len(resp.TransitIPs) != 0 {
		t.Fatalf("n TransitIPs in response: %d, want 0", len(resp.TransitIPs))
	}
}

// TestHandleConnectorTransitIPRequestStoresAddr tests that if sent a
// request with a transit addr and a destination addr we store that mapping
// and can retrieve it. If sent another req with a different dst for that transit addr
// we store that instead.
func TestHandleConnectorTransitIPRequestStoresAddr(t *testing.T) {
	c := &Conn25{}
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

	resp := c.HandleConnectorTransitIPRequest(nid, mr(tip, dip))
	if len(resp.TransitIPs) != 1 {
		t.Fatalf("n TransitIPs in response: %d, want 1", len(resp.TransitIPs))
	}
	got := resp.TransitIPs[0].Code
	if got != TransitIPResponseCode(0) {
		t.Fatalf("TransitIP Code: %d, want 0", got)
	}
	gotAddr := c.transitIPTarget(nid, tip)
	if gotAddr != dip {
		t.Fatalf("Connector stored destination for tip: %v, want %v", gotAddr, dip)
	}

	// mapping can be overwritten
	resp2 := c.HandleConnectorTransitIPRequest(nid, mr(tip, dip2))
	if len(resp2.TransitIPs) != 1 {
		t.Fatalf("n TransitIPs in response: %d, want 1", len(resp2.TransitIPs))
	}
	got2 := resp.TransitIPs[0].Code
	if got2 != TransitIPResponseCode(0) {
		t.Fatalf("TransitIP Code: %d, want 0", got2)
	}
	gotAddr2 := c.transitIPTarget(nid, tip)
	if gotAddr2 != dip2 {
		t.Fatalf("Connector stored destination for tip: %v, want %v", gotAddr, dip2)
	}
}

// TestHandleConnectorTransitIPRequestMultipleTIP tests that we can
// get a req with multiple mappings and we store them all. Including
// multiple transit addrs for the same destination.
func TestHandleConnectorTransitIPRequestMultipleTIP(t *testing.T) {
	c := &Conn25{}
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
	resp := c.HandleConnectorTransitIPRequest(nid, req)
	if len(resp.TransitIPs) != 3 {
		t.Fatalf("n TransitIPs in response: %d, want 3", len(resp.TransitIPs))
	}

	for i := 0; i < 3; i++ {
		got := resp.TransitIPs[i].Code
		if got != TransitIPResponseCode(0) {
			t.Fatalf("i=%d TransitIP Code: %d, want 0", i, got)
		}
	}
	gotAddr1 := c.transitIPTarget(nid, tip)
	if gotAddr1 != dip {
		t.Fatalf("Connector stored destination for tip(%v): %v, want %v", tip, gotAddr1, dip)
	}
	gotAddr2 := c.transitIPTarget(nid, tip2)
	if gotAddr2 != dip2 {
		t.Fatalf("Connector stored destination for tip(%v): %v, want %v", tip2, gotAddr2, dip2)
	}
	gotAddr3 := c.transitIPTarget(nid, tip3)
	if gotAddr3 != dip {
		t.Fatalf("Connector stored destination for tip(%v): %v, want %v", tip3, gotAddr3, dip)
	}
}

// TestHandleConnectorTransitIPRequestSameTIP tests that if we get
// a req that has more than one TransitIPRequest for the same transit addr
// only the first is stored, and the subsequent ones get an error code and
// message in the response.
func TestHandleConnectorTransitIPRequestSameTIP(t *testing.T) {
	c := &Conn25{}
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

	resp := c.HandleConnectorTransitIPRequest(nid, req)
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

	gotAddr1 := c.transitIPTarget(nid, tip)
	if gotAddr1 != dip {
		t.Fatalf("Connector stored destination for tip(%v): %v, want %v", tip, gotAddr1, dip)
	}
	gotAddr2 := c.transitIPTarget(nid, tip2)
	if gotAddr2 != dip3 {
		t.Fatalf("Connector stored destination for tip(%v): %v, want %v", tip2, gotAddr2, dip3)
	}
}

// TestGetDstIPUnknownTIP tests that unknown transit addresses can be looked up without problem.
func TestTransitIPTargetUnknownTIP(t *testing.T) {
	c := &Conn25{}
	nid := tailcfg.NodeID(1)
	tip := netip.MustParseAddr("0.0.0.1")
	got := c.transitIPTarget(nid, tip)
	want := netip.Addr{}
	if got != want {
		t.Fatalf("Unknown transit addr, want: %v, got %v", want, got)
	}
}

func TestPickSplitDNSPeers(t *testing.T) {
	getBytesForAttr := func(name string, domains []string) []byte {
		attr := appctype.Conn25Attr{
			Name:    name,
			Domains: domains,
		}
		bs, err := json.Marshal(attr)
		if err != nil {
			t.Fatalf("test setup: %v", err)
		}
		return bs
	}
	appOneBytes := getBytesForAttr("app1", []string{"example.com"})
	appTwoBytes := getBytesForAttr("app2", []string{"a.example.com"})
	appThreeBytes := getBytesForAttr("app3", []string{"woo.b.example.com", "hoo.b.example.com"})
	appFourBytes := getBytesForAttr("app4", []string{"woo.b.example.com", "c.example.com"})
	appFourDifferentDomainsBytes := getBytesForAttr("app4", []string{"example.com"})

	makeNodeView := func(id tailcfg.NodeID, name string, conn25Config []tailcfg.RawMessage) tailcfg.NodeView {
		return (&tailcfg.Node{
			ID:   id,
			Name: name,
			CapMap: tailcfg.NodeCapMap{
				tailcfg.NodeCapability("tailscale.com/conn25"): conn25Config,
			},
		}).View()
	}
	nvp1 := makeNodeView(1, "p1", []tailcfg.RawMessage{tailcfg.RawMessage(appOneBytes)})
	nvp2 := makeNodeView(2, "p2", []tailcfg.RawMessage{tailcfg.RawMessage(appFourBytes)})
	nvp3 := makeNodeView(3, "p3", []tailcfg.RawMessage{tailcfg.RawMessage(appTwoBytes), tailcfg.RawMessage(appThreeBytes)})
	nvp4 := makeNodeView(4, "p4", []tailcfg.RawMessage{tailcfg.RawMessage(appTwoBytes), tailcfg.RawMessage(appThreeBytes)})
	nvp6 := makeNodeView(6, "p6", []tailcfg.RawMessage{tailcfg.RawMessage(appFourDifferentDomainsBytes)})

	for _, tst := range []struct {
		name  string
		want  map[string][]tailcfg.NodeView
		peers []tailcfg.NodeView
	}{
		{
			name: "empty",
		},
		{
			name: "bad-peer",
			peers: []tailcfg.NodeView{
				(&tailcfg.Node{
					Name: "p1",
					CapMap: tailcfg.NodeCapMap{
						tailcfg.NodeCapability("tailscale.com/conn25"): []tailcfg.RawMessage{tailcfg.RawMessage(`hey`)},
					},
				}).View(),
			},
		},
		{
			name: "peers-with-config",
			peers: []tailcfg.NodeView{
				nvp1,
				nvp2,
				nvp3,
				nvp4,
				(&tailcfg.Node{
					ID:   5,
					Name: "p5",
				}).View(),
			},
			want: map[string][]tailcfg.NodeView{
				// p5 has no config and so doesn't appear
				"example.com":       {nvp1},
				"a.example.com":     {nvp3, nvp4},
				"woo.b.example.com": {nvp2, nvp3, nvp4},
				"hoo.b.example.com": {nvp3, nvp4},
				"c.example.com":     {nvp2},
			},
		},
		{
			name: "peers-disagree-over-which-domains-an-app-has",
			peers: []tailcfg.NodeView{
				nvp2,
				nvp6,
			},
			want: map[string][]tailcfg.NodeView{
				// p2 and p6 have ended up with different ideas of which domains app4 is handling.
				// We are ignoring app names and so it doesn't matter to us.
				"example.com":       {nvp6},
				"woo.b.example.com": {nvp2},
				"c.example.com":     {nvp2},
			},
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			m := map[tailcfg.NodeID]tailcfg.NodeView{}
			for i, p := range tst.peers {
				m[tailcfg.NodeID(i)] = p
			}
			got := PickSplitDNSPeers(func(_ tailcfg.NodeCapability) bool {
				return true
			}, m)
			if !reflect.DeepEqual(got, tst.want) {
				t.Fatalf("got %v, want %v", got, tst.want)
			}
		})
	}
}

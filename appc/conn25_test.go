// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
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

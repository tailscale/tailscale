package appc

import (
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
)

func TestHandleConnectorTransitIPRequest(t *testing.T) {
	c := &Conn25{}
	// specific to the peer making this request and
	// must be within the tailnet's TransitIP range.
	// If the connector already has a mapping for this TransitIP from this client, it will be replaced with the new mapping specified here.
	// It is an error to request the same TransitIP more than once in the same [ConnectorTransitIPRequest].

	req := ConnectorTransitIPRequest{}
	nid := tailcfg.NodeID(1)
	resp := c.HandleConnectorTransitIPRequest(nid, req)
	if len(resp.TransitIPs) != 0 {
		t.Fatal("shoulda been 0")
	}

	tip := netip.MustParseAddr("0.0.0.1")
	dip := netip.MustParseAddr("1.2.3.4")
	req = ConnectorTransitIPRequest{
		TransitIPs: []TransitIPRequest{
			{TransitIP: tip, DestinationIP: dip},
		},
	}
	resp = c.HandleConnectorTransitIPRequest(tailcfg.NodeID(1), req)
	if len(resp.TransitIPs) != 1 {
		t.Fatal("shoulda been 1")
	}
	if resp.TransitIPs[0].Code != TransitIPResponseCode(0) {
		t.Fatal("shoulda been 0")
	}
	func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		state, ok := c.transitIPMap[nid]
		if !ok {
			t.Fatal("shoulda found it")
		}
		stored, ok := state[tip]
		if !ok {
			t.Fatal("shoulda found it")
		}
		if stored != dip {
			t.Fatal("shoulda been dip")
		}
	}()
}

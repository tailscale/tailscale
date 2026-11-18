// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logid"
	"tailscale.com/types/netlogtype"
	"tailscale.com/util/must"
	"tailscale.com/util/zstdframe"
)

// TestNetLogTarget checks that network flow logs go to the
// [nodecap.LogFlowsTarget] control sends, and that they describe the
// traffic sent. An upload to Tailscale's log service instead would go
// through the env's traffic trap and fail the test.
func TestNetLogTarget(t *testing.T) {
	tstest.Parallel(t)
	domainID := must.Get(logid.NewPrivateID())
	env := NewTestEnv(t, ConfigureControl(func(s *testcontrol.Server) {
		s.ModifyFirstMapResponse = func(res *tailcfg.MapResponse, _ *tailcfg.MapRequest) {
			res.DomainDataPlaneAuditLogID = domainID.String()
		}
	}))

	type upload struct {
		uri  string
		msgs []netlogtype.Message
		err  error
	}
	var (
		mu      sync.Mutex
		uploads []upload
	)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := upload{uri: r.URL.RequestURI()}
		body, err := io.ReadAll(r.Body)
		if err == nil && r.Header.Get("Content-Encoding") == "zstd" {
			body, err = zstdframe.AppendDecode(nil, body)
		}
		if err == nil {
			err = json.Unmarshal(body, &u.msgs) // logtail uploads a JSON array of entries
		}
		u.err = err
		mu.Lock()
		uploads = append(uploads, u)
		mu.Unlock()
	}))
	defer target.Close()

	n1 := NewTestNode(t, env)
	d1 := n1.StartDaemon()
	n1.AwaitListening()
	n1.MustUp()
	n1.AwaitRunning()
	n2 := NewTestNode(t, env)
	d2 := n2.StartDaemon()
	n2.AwaitListening()
	n2.MustUp()
	n2.AwaitRunning()
	ip1, ip2 := n1.AwaitIP4(), n2.AwaitIP4()

	// enableNetLog has control turn on flow logging to target for n,
	// returning n's status and the URI its uploads must use.
	enableNetLog := func(n *TestNode) (*ipnstate.PeerStatus, string) {
		self := n.MustStatus().Self
		id := must.Get(logid.NewPrivateID())
		node := env.Control.Node(self.PublicKey)
		node.DataPlaneAuditLogID = id.String()
		env.Control.UpdateNode(node)
		env.Control.SetNodeCapMap(node.Key, tailcfg.NodeCapMap{
			nodecap.DataPlaneAuditLogs: nil,
			nodecap.LogFlowsTarget:     {tailcfg.RawMessage(`"` + target.URL + `/netlog/"`)},
		})
		return self, "/netlog/c/tailtraffic.log.tailscale.io/" + id.String() + "?copyId=" + domainID.String()
	}
	self1, uri1 := enableNetLog(n1)
	self2, uri2 := enableNetLog(n2)

	type flowLog struct {
		uri  string
		msg  netlogtype.Message
		flow netlogtype.ConnectionCounts
	}
	// findICMP returns the first uploaded ICMP flow from src to dst.
	findICMP := func(src, dst netip.Addr) (flowLog, bool) {
		mu.Lock()
		defer mu.Unlock()
		for _, u := range uploads {
			for _, m := range u.msgs {
				for _, c := range m.VirtualTraffic {
					if c.Proto == ipproto.ICMPv4 && c.Src.Addr() == src && c.Dst.Addr() == dst {
						return flowLog{u.uri, m, c}, true
					}
				}
			}
		}
		return flowLog{}, false
	}

	// Netstack consumes inbound packets before the TUN's counter sees them,
	// so each node logs only what it sent: n1 the requests, n2 the replies.
	var req, reply flowLog
	if err := tstest.WaitFor(30*time.Second, func() error {
		n1.Tailscale("ping", "--icmp", "--timeout=1s", ip2.String()).Run()
		var okReq, okReply bool
		req, okReq = findICMP(ip1, ip2)
		reply, okReply = findICMP(ip2, ip1)
		if !okReq || !okReply {
			return fmt.Errorf("target has request flow %v, reply flow %v", okReq, okReply)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	const icmpEchoHeaders = 20 + 8 // IPv4 + ICMP; tailscale ping sends no payload
	for _, tt := range []struct {
		name       string
		got        flowLog
		uri        string
		self, peer *ipnstate.PeerStatus
	}{
		{"request", req, uri1, self1, self2},
		{"reply", reply, uri2, self2, self1},
	} {
		m, f := tt.got.msg, tt.got.flow
		if tt.got.uri != tt.uri {
			t.Errorf("%s: uploaded to %q, want %q", tt.name, tt.got.uri, tt.uri)
		}
		if m.NodeID != tt.self.ID {
			t.Errorf("%s: nodeId = %q, want %q", tt.name, m.NodeID, tt.self.ID)
		}
		if m.Start.IsZero() || m.End.Before(m.Start) {
			t.Errorf("%s: time range = [%v, %v], want start <= end", tt.name, m.Start, m.End)
		}
		if m.SrcNode.NodeID != tt.self.ID || !slices.Contains(m.SrcNode.Addresses, f.Src.Addr()) {
			t.Errorf("%s: srcNode = %+v, want %q with %v", tt.name, m.SrcNode, tt.self.ID, f.Src.Addr())
		}
		if !slices.ContainsFunc(m.DstNodes, func(n netlogtype.Node) bool {
			return n.NodeID == tt.peer.ID && slices.Contains(n.Addresses, f.Dst.Addr())
		}) {
			t.Errorf("%s: dstNodes = %+v, want %q with %v", tt.name, m.DstNodes, tt.peer.ID, f.Dst.Addr())
		}
		if f.TxPackets == 0 || f.TxBytes < f.TxPackets*icmpEchoHeaders {
			t.Errorf("%s: counts = %+v, want >= %d bytes per sent packet", tt.name, f.Counts, icmpEchoHeaders)
		}
	}

	mu.Lock()
	for _, u := range uploads {
		if u.uri != uri1 && u.uri != uri2 {
			t.Errorf("upload to %q, want %q or %q", u.uri, uri1, uri2)
		}
		if u.err != nil {
			t.Errorf("upload to %q: %v", u.uri, u.err)
		}
	}
	mu.Unlock()

	d1.MustCleanShutdown(t)
	d2.MustCleanShutdown(t)
}

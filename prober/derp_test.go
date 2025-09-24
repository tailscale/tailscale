// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestDerpProber(t *testing.T) {
	dm := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			0: {
				RegionID:   0,
				RegionCode: "zero",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "n1",
						RegionID: 0,
						HostName: "derpn1.tailscale.test",
						IPv4:     "1.1.1.1",
						IPv6:     "::1",
					},
					{
						Name:     "n2",
						RegionID: 0,
						HostName: "derpn2.tailscale.test",
						IPv4:     "1.1.1.1",
						IPv6:     "::1",
					},
				},
			},
			1: {
				RegionID:   1,
				RegionCode: "one",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "n3",
						RegionID: 0,
						HostName: "derpn3.tailscale.test",
						IPv4:     "1.1.1.1",
						IPv6:     "::1",
					},
				},
			},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := json.Marshal(dm)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(resp)
	}))
	defer srv.Close()

	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker)
	dp := &derpProber{
		p:              p,
		derpMapURL:     srv.URL,
		tlsInterval:    time.Second,
		tlsProbeFn:     func(_ string, _ *tls.Config) ProbeClass { return FuncProbe(func(context.Context) error { return nil }) },
		udpInterval:    time.Second,
		udpProbeFn:     func(_ string, _ int) ProbeClass { return FuncProbe(func(context.Context) error { return nil }) },
		meshInterval:   time.Second,
		meshProbeFn:    func(_, _ string) ProbeClass { return FuncProbe(func(context.Context) error { return nil }) },
		nodes:          make(map[string]*tailcfg.DERPNode),
		probes:         make(map[string]*Probe),
		regionCodeOrID: "zero",
	}
	if err := dp.probeMapFn(context.Background()); err != nil {
		t.Errorf("unexpected probeMapFn() error: %s", err)
	}
	if len(dp.nodes) != 2 || dp.nodes["n1"] == nil || dp.nodes["n2"] == nil {
		t.Errorf("unexpected nodes: %+v", dp.nodes)
	}
	// Probes expected for two nodes:
	// - 3 regular probes per node (TLS, UDPv4, UDPv6)
	// - 4 mesh probes (N1->N2, N1->N1, N2->N1, N2->N2)
	if len(dp.probes) != 10 {
		t.Errorf("unexpected probes: %+v", dp.probes)
	}

	// Add one more node and check that probes got created.
	dm.Regions[0].Nodes = append(dm.Regions[0].Nodes, &tailcfg.DERPNode{
		Name:     "n4",
		RegionID: 0,
		HostName: "derpn4.tailscale.test",
		IPv4:     "1.1.1.1",
		IPv6:     "::1",
	})
	if err := dp.probeMapFn(context.Background()); err != nil {
		t.Errorf("unexpected probeMapFn() error: %s", err)
	}
	if len(dp.nodes) != 3 {
		t.Errorf("unexpected nodes: %+v", dp.nodes)
	}
	// 9 regular probes + 9 mesh probes
	if len(dp.probes) != 18 {
		t.Errorf("unexpected probes: %+v", dp.probes)
	}

	// Remove 2 nodes and check that probes have been destroyed.
	dm.Regions[0].Nodes = dm.Regions[0].Nodes[:1]
	if err := dp.probeMapFn(context.Background()); err != nil {
		t.Errorf("unexpected probeMapFn() error: %s", err)
	}
	if len(dp.nodes) != 1 {
		t.Errorf("unexpected nodes: %+v", dp.nodes)
	}
	// 3 regular probes + 1 mesh probe
	if len(dp.probes) != 4 {
		t.Errorf("unexpected probes: %+v", dp.probes)
	}

	// Stop filtering regions.
	dp.regionCodeOrID = ""
	if err := dp.probeMapFn(context.Background()); err != nil {
		t.Errorf("unexpected probeMapFn() error: %s", err)
	}
	if len(dp.nodes) != 2 {
		t.Errorf("unexpected nodes: %+v", dp.nodes)
	}
	// 6 regular probes + 2 mesh probe
	if len(dp.probes) != 8 {
		t.Errorf("unexpected probes: %+v", dp.probes)
	}
}

func TestRunDerpProbeNodePair(t *testing.T) {
	// os.Setenv("DERP_DEBUG_LOGS", "true")
	serverPrivateKey := key.NewNode()
	s := derpserver.New(serverPrivateKey, t.Logf)
	defer s.Close()

	httpsrv := &http.Server{
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      derpserver.Handler(s),
	}
	ln, err := net.Listen("tcp4", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	serverURL := "http://" + ln.Addr().String()
	t.Logf("server URL: %s", serverURL)

	go func() {
		if err := httpsrv.Serve(ln); err != nil {
			if err == http.ErrServerClosed {
				return
			}
			panic(err)
		}
	}()
	newClient := func() *derphttp.Client {
		c, err := derphttp.NewClient(key.NewNode(), serverURL, t.Logf, netmon.NewStatic())
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		m, err := c.Recv()
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		switch m.(type) {
		case derp.ServerInfoMessage:
		default:
			t.Fatalf("unexpected first message type %T", m)
		}
		return c
	}

	c1 := newClient()
	defer c1.Close()
	c2 := newClient()
	defer c2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err = runDerpProbeNodePair(ctx, &tailcfg.DERPNode{Name: "c1"}, &tailcfg.DERPNode{Name: "c2"}, c1, c2, 100_000_000)
	if err != nil {
		t.Error(err)
	}
}

func Test_packetsForSize(t *testing.T) {
	tests := []struct {
		name        string
		size        int
		wantPackets int
		wantUnique  bool
	}{
		{"small_unqiue", 8, 1, true},
		{"8k_unique", 8192, 1, true},
		{"full_size_packet", derp.MaxPacketSize, 1, true},
		{"larger_than_one", derp.MaxPacketSize + 1, 2, false},
		{"large", 500000, 8, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashes := make(map[string]int)
			for range 5 {
				pkts := packetsForSize(int64(tt.size))
				if len(pkts) != tt.wantPackets {
					t.Errorf("packetsForSize(%d) got %d packets, want %d", tt.size, len(pkts), tt.wantPackets)
				}
				var total int
				hash := sha256.New()
				for _, p := range pkts {
					hash.Write(p)
					total += len(p)
				}
				hashes[string(hash.Sum(nil))]++
				if total != tt.size {
					t.Errorf("packetsForSize(%d) returned %d bytes total", tt.size, total)
				}
			}
			unique := len(hashes) > 1
			if unique != tt.wantUnique {
				t.Errorf("packetsForSize(%d) is unique=%v (returned %d different answers); want unique=%v", tt.size, unique, len(hashes), unique)
			}
		})
	}
}

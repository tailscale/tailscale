// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package prober

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/tailcfg"
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
		p:           p,
		derpMapURL:  srv.URL,
		tlsProbeFn:  func(_ string) ProbeFunc { return func(context.Context) error { return nil } },
		udpProbeFn:  func(_ string, _ int) ProbeFunc { return func(context.Context) error { return nil } },
		meshProbeFn: func(_, _ string) ProbeFunc { return func(context.Context) error { return nil } },
		nodes:       make(map[string]*tailcfg.DERPNode),
		probes:      make(map[string]*Probe),
	}
	if err := dp.ProbeMap(context.Background()); err != nil {
		t.Errorf("unexpected ProbeMap() error: %s", err)
	}
	if len(dp.nodes) != 2 || dp.nodes["derpn1.tailscale.test"] == nil || dp.nodes["derpn2.tailscale.test"] == nil {
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
		Name:     "n3",
		RegionID: 0,
		HostName: "derpn3.tailscale.test",
		IPv4:     "1.1.1.1",
		IPv6:     "::1",
	})
	if err := dp.ProbeMap(context.Background()); err != nil {
		t.Errorf("unexpected ProbeMap() error: %s", err)
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
	if err := dp.ProbeMap(context.Background()); err != nil {
		t.Errorf("unexpected ProbeMap() error: %s", err)
	}
	if len(dp.nodes) != 1 {
		t.Errorf("unexpected nodes: %+v", dp.nodes)
	}
	// 3 regular probes + 1 mesh probe
	if len(dp.probes) != 4 {
		t.Errorf("unexpected probes: %+v", dp.probes)
	}
}

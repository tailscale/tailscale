// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"testing"
	"time"

	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestPortmapCreate checks whether a disco ping reaches a node directly when
// its router offers the given port mapping services, and which protocol the
// client uses to create its mapping.
func TestPortmapCreate(t *testing.T) {
	tests := []struct {
		name        string
		pinger      vmtest.AddNodeFunc
		targetNAT   vnet.NAT
		targetSvcs  []vnet.NetworkService
		wantDirect  bool
		wantMapping vnet.NetworkService // empty if no mapping is expected
		altMapping  vnet.NetworkService // also accepted, if not empty
	}{
		// No portmapping protocols available
		{
			name:       "none",
			pinger:     hard,
			targetNAT:  vnet.HardNAT,
			wantDirect: false,
		},
		{
			name:        "not-needed",
			pinger:      easyAF, // addr-only filtering => no portmapping needed
			targetNAT:   vnet.HardNAT,
			wantDirect:  true,
			wantMapping: "",
		},
		// Normal cases (portmapping required for direct connections)
		{
			name:        "pcp-only",
			pinger:      hard,
			targetNAT:   vnet.HardNAT,
			targetSvcs:  []vnet.NetworkService{vnet.PCP},
			wantDirect:  true,
			wantMapping: vnet.PCP,
		},
		{
			name:        "pmp-only",
			pinger:      hard,
			targetNAT:   vnet.HardNAT,
			targetSvcs:  []vnet.NetworkService{vnet.NATPMP},
			wantDirect:  true,
			wantMapping: vnet.NATPMP,
		},
		{
			name:        "upnp-only",
			pinger:      hard,
			targetNAT:   vnet.HardNAT,
			targetSvcs:  []vnet.NetworkService{vnet.UPnP},
			wantDirect:  true,
			wantMapping: vnet.UPnP,
		},
		{
			name:        "pcp-and-pmp",
			pinger:      hard,
			targetNAT:   vnet.HardNAT,
			targetSvcs:  []vnet.NetworkService{vnet.PCP, vnet.NATPMP},
			wantDirect:  true,
			wantMapping: vnet.NATPMP,
		},
		{
			name:        "pcp-and-upnp",
			pinger:      hard,
			targetNAT:   vnet.HardNAT,
			targetSvcs:  []vnet.NetworkService{vnet.PCP, vnet.UPnP},
			wantDirect:  true,
			wantMapping: vnet.PCP,
			// TODO(fmarier): the client sometimes uses UPnP here. Before
			// its first probe, it tries NAT-PMP and ignores the router's
			// PCP "unsupported version" reply (tailscale#21799). After a
			// timeout, it falls back to UPnP. If the probe hasn't found the
			// UPnP server yet, that fails and the next attempt uses PCP.
			// Remove this field once we have stabilized which protocol we get.
			altMapping: vnet.UPnP,
		},
		{
			name:        "pmp-and-upnp",
			pinger:      hard,
			targetNAT:   vnet.HardNAT,
			targetSvcs:  []vnet.NetworkService{vnet.NATPMP, vnet.UPnP},
			wantDirect:  true,
			wantMapping: vnet.NATPMP,
		},
		{
			name:        "all",
			pinger:      hard,
			targetNAT:   vnet.HardNAT,
			targetSvcs:  []vnet.NetworkService{vnet.PCP, vnet.NATPMP, vnet.UPnP},
			wantDirect:  true,
			wantMapping: vnet.NATPMP,
		},
		// Portmapping also needed behind EasyNAT (endpoint-independent mapping,
		// but addr+port filtering)
		{
			name:        "easy-all",
			pinger:      hard,
			targetNAT:   vnet.EasyNAT,
			targetSvcs:  []vnet.NetworkService{vnet.PCP, vnet.NATPMP, vnet.UPnP},
			wantDirect:  true,
			wantMapping: vnet.NATPMP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := vmtest.New(t)
			pinger := tt.pinger(env)
			n := env.NumNodes()
			opts := []any{
				fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
				fmt.Sprintf("10.7.%d.1/24", n),
				tt.targetNAT,
			}
			for _, s := range tt.targetSvcs {
				opts = append(opts, s)
			}
			router := env.AddNetwork(opts...)
			target := env.AddNode(fmt.Sprintf("node-%d", n), router)
			env.Start()

			res, err := env.PingSettle(pinger, target, 15*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if gotDirect := res.Endpoint != ""; gotDirect != tt.wantDirect {
				t.Fatalf("ping direct = %v (endpoint %q), want %v", gotDirect, res.Endpoint, tt.wantDirect)
			}

			mappings := router.PortMappings()
			if tt.wantMapping == "" {
				if len(mappings) != 0 {
					t.Errorf("got port mappings %v, want none", mappings)
				}
				return
			}
			if len(mappings) != 1 {
				t.Fatalf("got port mappings %v, want one", mappings)
			}
			for wan, pm := range mappings {
				if got := pm.Service; got != tt.wantMapping && got != tt.altMapping {
					t.Errorf("port mapping made with %v, want %v", got, tt.wantMapping)
				}
				if want := wan.String(); want != res.Endpoint {
					t.Errorf("ping went to %v, want port mapped endpoint %v", res.Endpoint, want)
				}
			}
		})
	}
}

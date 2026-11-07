// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

func checkPing(t *testing.T, env *vmtest.Env, from, to *vmtest.Node, wantDirect bool) (endpoint string) {
	t.Helper()
	res, err := env.PingSettle(from, to, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if gotDirect := res.Endpoint != ""; gotDirect != wantDirect {
		t.Fatalf("ping direct = %v (endpoint %q), want %v", gotDirect, res.Endpoint, wantDirect)
	}
	return res.Endpoint
}

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
			t.Parallel()
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

			endpoint := checkPing(t, env, pinger, target, tt.wantDirect)

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
				if endpoint != wan.String() {
					t.Errorf("ping went to %v, want port mapped endpoint %v", endpoint, wan)
				}
			}
		})
	}
}

// TestPortmapRenew checks that a node renews its port mapping before it
// expires when its router grants a short lifetime.
func TestPortmapRenew(t *testing.T) {
	// TODO(fmarier): run by default once there is a debug interface
	// (https://github.com/tailscale/corp/issues/48412), and drop this
	// test from the exclude list in .github/workflows/natlab-test.yml.
	skipIfNotSlowTests(t)
	tests := []struct {
		name string
		svc  vnet.NetworkService
	}{
		{"pcp-only", vnet.PCP},
		{"natpmp-only", vnet.NATPMP},
		// TODO(fmarier): add a UPnP case. Tailscale clients request 7200s leases
		// and the AddAnyPortMapping response has no way to grant a shorter one,
		// so doing the same as PCP/NAT-PMP would take an hour or more.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := vmtest.New(t)
			pinger := hard(env)
			n := env.NumNodes()
			router := env.AddNetwork(
				fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
				fmt.Sprintf("10.7.%d.1/24", n),
				vnet.HardNAT,
				tt.svc,
			)
			// The client renews after half the lifetime, on its next periodic
			// re-STUN (every 20-26s), so the lifetime must be > 52s on KVM,
			// much longer on VMs without hardware acceleration.
			lifetime := 2 * time.Minute
			router.SetPortMapLifetime(lifetime)
			target := env.AddNode(fmt.Sprintf("node-%d", n), router)
			env.Start()

			checkPing(t, env, pinger, target, true)
			mappings := router.PortMappings()
			if len(mappings) != 1 {
				t.Fatalf("got port mappings %v, want one", mappings)
			}
			var wan netip.AddrPort
			var expiry time.Time
			for k, pm := range mappings {
				wan, expiry = k, pm.ExpiresAt
			}
			if time.Until(expiry) > lifetime {
				t.Fatalf("port mapping expires at %v, want within %v", expiry, lifetime)
			}

			var lastPing time.Time
			for {
				// Prevent target from going idle and stopping periodic re-STUN that triggers renewals.
				if time.Since(lastPing) >= 10*time.Second {
					if err := env.Ping(pinger, target, tailcfg.PingTSMP, 5*time.Second); err != nil {
						t.Fatal(err)
					}
					lastPing = time.Now()
				}

				mappings := router.PortMappings()
				pm, ok := mappings[wan]
				if !ok || len(mappings) != 1 || pm.Service != tt.svc {
					t.Fatalf("got port mappings %v, want only %v made with %v", mappings, wan, tt.svc)
				}
				if pm.ExpiresAt.After(expiry) {
					if renewed := pm.ExpiresAt.Add(-lifetime); renewed.After(expiry) {
						t.Fatalf("port mapping renewed at %v, after it expired at %v", renewed, expiry)
					}
					break // successful renewal
				}

				time.Sleep(time.Second)
			}

			// Wait for the original mapping to expire.
			time.Sleep(time.Until(expiry) + time.Second)
			endpoint := checkPing(t, env, pinger, target, true) // requires renewed portmap
			if endpoint != wan.String() {
				t.Errorf("ping went to %v, want port mapped endpoint %v", endpoint, wan)
			}
		})
	}
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

// TestEnsureCertLoops tests that the certManager correctly starts and stops
// update loops for certs when the serve config changes. It tracks goroutine
// count and uses that as a validator that the expected number of cert loops are
// running.
func TestEnsureCertLoops(t *testing.T) {
	tests := []struct {
		name              string
		initialConfig     *ipn.ServeConfig
		updatedConfig     *ipn.ServeConfig
		initialGoroutines int64 // after initial serve config is applied
		updatedGoroutines int64 // after updated serve config is applied
		wantErr           bool
	}{
		{
			name:              "empty_serve_config",
			initialConfig:     &ipn.ServeConfig{},
			initialGoroutines: 0,
		},
		{
			name:              "nil_serve_config",
			initialConfig:     nil,
			initialGoroutines: 0,
			wantErr:           true,
		},
		{
			name:          "empty_to_one_service",
			initialConfig: &ipn.ServeConfig{},
			updatedConfig: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:my-app": {
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"my-app.tailnetxyz.ts.net:443": {},
						},
					},
				},
			},
			initialGoroutines: 0,
			updatedGoroutines: 1,
		},
		{
			name: "single_service",
			initialConfig: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:my-app": {
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"my-app.tailnetxyz.ts.net:443": {},
						},
					},
				},
			},
			initialGoroutines: 1,
		},
		{
			name: "multiple_services",
			initialConfig: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:my-app": {
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"my-app.tailnetxyz.ts.net:443": {},
						},
					},
					"svc:my-other-app": {
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"my-other-app.tailnetxyz.ts.net:443": {},
						},
					},
				},
			},
			initialGoroutines: 2, // one loop per domain across all services
		},
		{
			name: "ignore_non_https_ports",
			initialConfig: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:my-app": {
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"my-app.tailnetxyz.ts.net:443": {},
							"my-app.tailnetxyz.ts.net:80":  {},
						},
					},
				},
			},
			initialGoroutines: 1, // only one loop for the 443 endpoint
		},
		{
			name: "remove_domain",
			initialConfig: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:my-app": {
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"my-app.tailnetxyz.ts.net:443": {},
						},
					},
					"svc:my-other-app": {
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"my-other-app.tailnetxyz.ts.net:443": {},
						},
					},
				},
			},
			updatedConfig: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:my-app": {
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"my-app.tailnetxyz.ts.net:443": {},
						},
					},
				},
			},
			initialGoroutines: 2, // initially two loops (one per service)
			updatedGoroutines: 1, // one loop after removing service2
		},
		{
			name: "add_domain",
			initialConfig: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:my-app": {
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"my-app.tailnetxyz.ts.net:443": {},
						},
					},
				},
			},
			updatedConfig: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:my-app": {
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"my-app.tailnetxyz.ts.net:443": {},
						},
					},
					"svc:my-other-app": {
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"my-other-app.tailnetxyz.ts.net:443": {},
						},
					},
				},
			},
			initialGoroutines: 1,
			updatedGoroutines: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cm := &certManager{
				lc:        &fakeLocalClient{},
				certLoops: make(map[string]context.CancelFunc),
			}

			allDone := make(chan bool, 1)
			defer cm.tracker.AddDoneCallback(func() {
				cm.mu.Lock()
				defer cm.mu.Unlock()
				if cm.tracker.RunningGoroutines() > 0 {
					return
				}
				select {
				case allDone <- true:
				default:
				}
			})()

			err := cm.ensureCertLoops(ctx, tt.initialConfig)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ensureCertLoops() error = %v", err)
			}

			if got := cm.tracker.RunningGoroutines(); got != tt.initialGoroutines {
				t.Errorf("after initial config: got %d running goroutines, want %d", got, tt.initialGoroutines)
			}

			if tt.updatedConfig != nil {
				if err := cm.ensureCertLoops(ctx, tt.updatedConfig); err != nil {
					t.Fatalf("ensureCertLoops() error on update = %v", err)
				}

				// Although starting goroutines and cancelling
				// the context happens in the main goroutine, it
				// the actual goroutine exit when a context is
				// cancelled does not- so wait for a bit for the
				// running goroutine count to reach the expected
				// number.
				deadline := time.After(5 * time.Second)
				for {
					if got := cm.tracker.RunningGoroutines(); got == tt.updatedGoroutines {
						break
					}
					select {
					case <-deadline:
						t.Fatalf("timed out waiting for goroutine count to reach %d, currently at %d",
							tt.updatedGoroutines, cm.tracker.RunningGoroutines())
					case <-time.After(10 * time.Millisecond):
						continue
					}
				}
			}

			if tt.updatedGoroutines == 0 {
				return // no goroutines to wait for
			}
			// cancel context to make goroutines exit
			cancel()
			select {
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for goroutine to finish")
			case <-allDone:
			}
		})
	}
}

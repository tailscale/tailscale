// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package certs

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/kube/localclient"
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
			name: "tcp_terminate_tls",
			initialConfig: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:my-apiserver": {
						TCP: map[uint16]*ipn.TCPPortHandler{
							443: {
								TCPForward:   "localhost:80",
								TerminateTLS: "my-apiserver.tailnetxyz.ts.net",
							},
						},
					},
				},
			},
			initialGoroutines: 1,
		},
		{
			name: "tcp_terminate_tls_and_web",
			initialConfig: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:my-apiserver": {
						TCP: map[uint16]*ipn.TCPPortHandler{
							443: {
								TCPForward:   "localhost:80",
								TerminateTLS: "my-apiserver.tailnetxyz.ts.net",
							},
						},
					},
					"svc:my-app": {
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"my-app.tailnetxyz.ts.net:443": {},
						},
					},
				},
			},
			initialGoroutines: 2,
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

			notifyChan := make(chan ipn.Notify)
			go func() {
				// SelfChange wakes the cert manager; cert domains are
				// then fetched via FakeLocalClient.CertDomainsResult.
				for {
					notifyChan <- ipn.Notify{
						SelfChange: &tailcfg.Node{StableID: "test"},
					}
				}
			}()
			cm := &CertManager{
				lc: &localclient.FakeLocalClient{
					FakeIPNBusWatcher: localclient.FakeIPNBusWatcher{
						NotifyChan: notifyChan,
					},
					CertDomainsResult: []string{
						"my-app.tailnetxyz.ts.net",
						"my-other-app.tailnetxyz.ts.net",
						"my-apiserver.tailnetxyz.ts.net",
					},
				},
				logf:      log.Printf,
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

			err := cm.EnsureCertLoops(ctx, tt.initialConfig)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ensureCertLoops() error = %v", err)
			}

			if got := cm.tracker.RunningGoroutines(); got != tt.initialGoroutines {
				t.Errorf("after initial config: got %d running goroutines, want %d", got, tt.initialGoroutines)
			}

			if tt.updatedConfig != nil {
				if err := cm.EnsureCertLoops(ctx, tt.updatedConfig); err != nil {
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

func TestIsTransientCertErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"deadline", context.DeadlineExceeded, true},
		{"canceled", context.Canceled, true},
		{"wrapped_deadline", fmt.Errorf("wrap: %w", context.DeadlineExceeded), true},
		{"connrefused", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), true},
		{"connreset", fmt.Errorf("read: %w", syscall.ECONNRESET), true},
		{"random", errors.New("badNonce"), false},
		{"rate_limited", &local.RateLimitedError{RetryAfter: time.Minute}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTransientCertErr(tt.err); got != tt.want {
				t.Errorf("isTransientCertErr(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestNextRetryInterval(t *testing.T) {
	const normal = 24 * time.Hour
	tests := []struct {
		name           string
		err            error
		startCount     int
		wantCount      int
		wantInterval   time.Duration
	}{
		{"success", nil, 5, 0, normal},
		{"transient_no_advance", context.DeadlineExceeded, 3, 3, retrySchedule[0]},
		{"rate_limit_with_hint", &local.RateLimitedError{RetryAfter: 17 * time.Minute}, 0, 1, 17 * time.Minute},
		{"rate_limit_no_hint", &local.RateLimitedError{}, 0, 1, retrySchedule[0]},
		{"other_advances", errors.New("badNonce"), 0, 1, retrySchedule[0]},
		{"other_clamps", errors.New("badNonce"), len(retrySchedule) + 3, len(retrySchedule) + 4, retrySchedule[len(retrySchedule)-1]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.startCount
			got := nextRetryInterval(tt.err, &c, normal)
			if c != tt.wantCount {
				t.Errorf("retryCount = %d, want %d", c, tt.wantCount)
			}
			if got != tt.wantInterval {
				t.Errorf("interval = %v, want %v", got, tt.wantInterval)
			}
		})
	}
}

func TestWaitForCertDomainHeartbeat(t *testing.T) {
	prev := waitForCertDomainHeartbeat
	waitForCertDomainHeartbeat = 20 * time.Millisecond
	defer func() { waitForCertDomainHeartbeat = prev }()

	var hits atomic.Int32
	logf := func(format string, args ...any) {
		if format == "cert: still waiting for domain %s in netmap (%v elapsed)" {
			hits.Add(1)
		}
	}

	notifyChan := make(chan ipn.Notify) // never closed, never sent to
	cm := &CertManager{
		lc: &localclient.FakeLocalClient{
			FakeIPNBusWatcher: localclient.FakeIPNBusWatcher{NotifyChan: notifyChan},
		},
		logf: logf,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cm.waitForCertDomain(ctx, "foo.tailnetxyz.ts.net") }()

	// Wait for at least two heartbeats.
	deadline := time.Now().Add(2 * time.Second)
	for hits.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() < 2 {
		cancel()
		t.Fatalf("expected >=2 heartbeats, got %d", hits.Load())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("waitForCertDomain did not return after ctx cancel")
	}
}

// blockingLocalClient is a LocalClient whose CertPair blocks until release is
// closed, used to verify Shutdown waits for in-flight loops.
type blockingLocalClient struct {
	localclient.FakeLocalClient
	release chan struct{}
	mu      sync.Mutex
	calls   int
}

func (b *blockingLocalClient) CertPair(_ context.Context, _ string) ([]byte, []byte, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	<-b.release // intentionally ignores ctx so we can verify Shutdown waits.
	return nil, nil, nil
}

func TestShutdownWaitsForLoops(t *testing.T) {
	prev := initialJitter
	initialJitter = 1 * time.Millisecond
	defer func() { initialJitter = prev }()

	notifyChan := make(chan ipn.Notify, 1)
	notifyChan <- ipn.Notify{SelfChange: &tailcfg.Node{StableID: "x"}}

	blc := &blockingLocalClient{
		FakeLocalClient: localclient.FakeLocalClient{
			FakeIPNBusWatcher: localclient.FakeIPNBusWatcher{NotifyChan: notifyChan},
			CertDomainsResult: []string{"foo.tailnetxyz.ts.net"},
		},
		release: make(chan struct{}),
	}
	cm := &CertManager{lc: blc, logf: log.Printf, certLoops: map[string]context.CancelFunc{}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := cm.EnsureCertLoops(ctx, &ipn.ServeConfig{
		Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
			"svc:foo": {Web: map[ipn.HostPort]*ipn.WebServerConfig{"foo.tailnetxyz.ts.net:443": {}}},
		},
	}); err != nil {
		t.Fatalf("EnsureCertLoops: %v", err)
	}

	// Wait for CertPair to be entered (so we know a loop is mid-flight).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		blc.mu.Lock()
		n := blc.calls
		blc.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	shutdownDone := make(chan error, 1)
	go func() {
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		shutdownDone <- cm.Shutdown(sctx)
	}()

	// Shutdown must NOT return while CertPair is blocked.
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned early with %v while CertPair was in flight", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(blc.release) // unblock CertPair so the loop can exit
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return after loops were released")
	}
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/kube/localclient"
	"tailscale.com/tailcfg"
)

func TestUpdateServeConfig(t *testing.T) {
	tests := []struct {
		name       string
		sc         *ipn.ServeConfig
		certDomain string
		wantCall   bool
	}{
		{
			name: "no_https_no_cert_domain",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					80: {HTTP: true},
				},
			},
			certDomain: kubetypes.ValueNoHTTPS, // tailnet has HTTPS disabled
			wantCall:   true,                   // should set serve config as it doesn't have HTTPS endpoints
		},
		{
			name: "https_with_cert_domain",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {HTTPS: true},
				},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"${TS_CERT_DOMAIN}:443": {
						Handlers: map[string]*ipn.HTTPHandler{
							"/": {Proxy: "http://10.0.1.100:8080"},
						},
					},
				},
			},
			certDomain: "test-node.tailnet.ts.net",
			wantCall:   true,
		},
		{
			name: "https_without_cert_domain",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {HTTPS: true},
				},
			},
			certDomain: kubetypes.ValueNoHTTPS,
			wantCall:   false, // incorrect configuration- should not set serve config
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeLC := &localclient.FakeLocalClient{}
			applied, err := updateServeConfig(context.Background(), tt.sc, tt.certDomain, fakeLC)
			if err != nil {
				t.Errorf("updateServeConfig() error = %v", err)
			}
			if applied != tt.wantCall {
				t.Errorf("updateServeConfig() applied = %v, want %v", applied, tt.wantCall)
			}
			if fakeLC.SetServeCalled != tt.wantCall {
				t.Errorf("SetServeConfig() called = %v, want %v", fakeLC.SetServeCalled, tt.wantCall)
			}
		})
	}
}

func TestReadServeConfig(t *testing.T) {
	tests := []struct {
		name       string
		gotSC      string
		certDomain string
		wantSC     *ipn.ServeConfig
		wantErr    bool
	}{
		{
			name: "empty_file",
		},
		{
			name: "valid_config_with_cert_domain_placeholder",
			gotSC: `{
				"TCP": {
					"443": {
						"HTTPS": true
					}
				},
				"Web": {
					"${TS_CERT_DOMAIN}:443": {
					"Handlers": {
						"/api": {
							"Proxy": "https://10.2.3.4/api"
						}}}}}`,
			certDomain: "example.com",
			wantSC: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {
						HTTPS: true,
					},
				},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					ipn.HostPort("example.com:443"): {
						Handlers: map[string]*ipn.HTTPHandler{
							"/api": {
								Proxy: "https://10.2.3.4/api",
							},
						},
					},
				},
			},
		},
		{
			name: "valid_config_for_http_proxy",
			gotSC: `{
				"TCP": {
					"80": {
						"HTTP": true
					}
				}}`,
			wantSC: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					80: {
						HTTP: true,
					},
				},
			},
		},
		{
			name: "config_without_cert_domain",
			gotSC: `{
				"TCP": {
					"443": {
						"HTTPS": true
					}
				},
				"Web": {
					"localhost:443": {
					"Handlers": {
						"/api": {
							"Proxy": "https://10.2.3.4/api"
						}}}}}`,
			certDomain: "",
			wantErr:    false,
			wantSC: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {
						HTTPS: true,
					},
				},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					ipn.HostPort("localhost:443"): {
						Handlers: map[string]*ipn.HTTPHandler{
							"/api": {
								Proxy: "https://10.2.3.4/api",
							},
						},
					},
				},
			},
		},
		{
			name:    "invalid_json",
			gotSC:   "invalid json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "serve-config.json")
			if err := os.WriteFile(path, []byte(tt.gotSC), 0644); err != nil {
				t.Fatal(err)
			}

			got, err := readServeConfig(path, tt.certDomain)
			if (err != nil) != tt.wantErr {
				t.Errorf("readServeConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !cmp.Equal(got, tt.wantSC) {
				t.Errorf("readServeConfig() diff (-got +want):\n%s", cmp.Diff(got, tt.wantSC))
			}
		})
	}
}

func TestRefreshAdvertiseServices(t *testing.T) {
	tests := []struct {
		name                string
		sc                  *ipn.ServeConfig
		wantServices        []string
		wantEditPrefsCalled bool
		wantErr             bool
	}{
		{
			name:                "nil_serve_config",
			sc:                  nil,
			wantEditPrefsCalled: false,
		},
		{
			name:                "empty_serve_config",
			sc:                  &ipn.ServeConfig{},
			wantEditPrefsCalled: false,
		},
		{
			name: "no_services_defined",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					80: {HTTP: true},
				},
			},
			wantEditPrefsCalled: false,
		},
		{
			name: "single_service",
			sc: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:my-service": {},
				},
			},
			wantServices:        []string{"svc:my-service"},
			wantEditPrefsCalled: true,
		},
		{
			name: "multiple_services",
			sc: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:service-a": {},
					"svc:service-b": {},
					"svc:service-c": {},
				},
			},
			wantServices:        []string{"svc:service-a", "svc:service-b", "svc:service-c"},
			wantEditPrefsCalled: true,
		},
		{
			name: "services_with_tcp_and_web",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					80: {HTTP: true},
				},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"example.com:443": {},
				},
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:frontend": {},
					"svc:backend":  {},
				},
			},
			wantServices:        []string{"svc:frontend", "svc:backend"},
			wantEditPrefsCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run in a synctest bubble so that the 20 second
			// post-EditPrefs failover wait in
			// services.EnsureServicesAdvertised elapses on the fake
			// clock instead of taking 20 seconds of wall time per
			// subtest.
			synctest.Test(t, func(t *testing.T) {
				fakeLC := &localclient.FakeLocalClient{}
				err := refreshAdvertiseServices(t.Context(), tt.sc, fakeLC)

				if (err != nil) != tt.wantErr {
					t.Errorf("refreshAdvertiseServices() error = %v, wantErr %v", err, tt.wantErr)
				}

				if tt.wantEditPrefsCalled != (len(fakeLC.EditPrefsCalls) > 0) {
					t.Errorf("EditPrefs called = %v, want %v", len(fakeLC.EditPrefsCalls) > 0, tt.wantEditPrefsCalled)
				}

				if tt.wantEditPrefsCalled {
					if len(fakeLC.EditPrefsCalls) != 1 {
						t.Fatalf("expected 1 EditPrefs call, got %d", len(fakeLC.EditPrefsCalls))
					}

					mp := fakeLC.EditPrefsCalls[0]
					if !mp.AdvertiseServicesSet {
						t.Error("AdvertiseServicesSet should be true")
					}

					if len(mp.AdvertiseServices) != len(tt.wantServices) {
						t.Errorf("AdvertiseServices length = %d, want %d", len(mp.Prefs.AdvertiseServices), len(tt.wantServices))
					}

					advertised := make(map[string]bool)
					for _, svc := range mp.AdvertiseServices {
						advertised[svc] = true
					}

					for _, want := range tt.wantServices {
						if !advertised[want] {
							t.Errorf("expected service %q to be advertised, but it wasn't", want)
						}
					}
				}
			})
		})
	}
}

func TestHasHTTPSEndpoint(t *testing.T) {
	tests := []struct {
		name string
		cfg  *ipn.ServeConfig
		want bool
	}{
		{
			name: "nil_config",
			cfg:  nil,
			want: false,
		},
		{
			name: "empty_config",
			cfg:  &ipn.ServeConfig{},
			want: false,
		},
		{
			name: "no_https_endpoints",
			cfg: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					80: {
						HTTPS: false,
					},
				},
			},
			want: false,
		},
		{
			name: "has_https_endpoint",
			cfg: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {
						HTTPS: true,
					},
				},
			},
			want: true,
		},
		{
			name: "mixed_endpoints",
			cfg: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					80:  {HTTPS: false},
					443: {HTTPS: true},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasHTTPSEndpoint(tt.cfg)
			if got != tt.want {
				t.Errorf("hasHTTPSEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

type recordingServeClient struct {
	localclient.FakeLocalClient
	calls            []string
	applied          *ipn.ServeConfig
	advertisedConfig *ipn.ServeConfig
	setServeErr      error
}

func (c *recordingServeClient) SetServeConfig(ctx context.Context, sc *ipn.ServeConfig) error {
	c.calls = append(c.calls, "SetServeConfig")
	if c.setServeErr != nil {
		return c.setServeErr
	}
	c.applied = sc
	return c.FakeLocalClient.SetServeConfig(ctx, sc)
}

func (c *recordingServeClient) EditPrefs(ctx context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	c.calls = append(c.calls, "EditPrefs")
	c.advertisedConfig = c.applied
	return c.FakeLocalClient.EditPrefs(ctx, mp)
}

func TestUpdateServeConfigError(t *testing.T) {
	wantErr := errors.New("cannot apply serve config")
	client := &recordingServeClient{setServeErr: wantErr}
	applied, err := updateServeConfig(t.Context(), &ipn.ServeConfig{}, "", client)
	if applied || !errors.Is(err, wantErr) {
		t.Errorf("updateServeConfig = (%v, %v), want (false, %v)", applied, err, wantErr)
	}
}

func TestWatchServeConfigChangesAdvertisesServices(t *testing.T) {
	tests := []struct {
		name          string
		certShareMode string
		autoAdvertise string
	}{
		{name: "default", autoAdvertise: "true"},
		{name: "read_only_certs", certShareMode: "ro", autoAdvertise: "true"},
		{name: "read_write_certs", certShareMode: "rw", autoAdvertise: "true"},
		{name: "operator_managed", autoAdvertise: "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TS_EXPERIMENTAL_SERVICE_AUTO_ADVERTISEMENT", tt.autoAdvertise)
			path := filepath.Join(t.TempDir(), "serve.json")
			sc := &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:frontend": {TCP: map[uint16]*ipn.TCPPortHandler{80: {TCPForward: "127.0.0.1:8080"}}},
					"svc:backend":  {TCP: map[uint16]*ipn.TCPPortHandler{80: {TCPForward: "127.0.0.1:8081"}}},
				},
			}
			b, err := json.Marshal(sc)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var certDomain atomic.Pointer[string]
				certDomain.Store(new("test-node.tailnet.ts.net"))
				changed := make(chan bool, 1)
				client := &recordingServeClient{}
				done := make(chan struct{})
				go func() {
					defer close(done)
					watchServeConfigChangesLoop(ctx, changed, &certDomain, client, nil, &settings{
						ServeConfigPath: path,
						CertShareMode:   tt.certShareMode,
					}, nil, nil, nil)
				}()
				changed <- true
				synctest.Wait()
				// Let advertisement finish, then check that an unchanged file
				// does not reapply handlers or advertise again.
				time.Sleep(20 * time.Second)
				synctest.Wait()
				changed <- true
				synctest.Wait()
				cancel()
				<-done
				wantCalls := []string{"SetServeConfig"}
				if tt.autoAdvertise == "true" {
					wantCalls = append(wantCalls, "EditPrefs")
				}
				if diff := cmp.Diff(wantCalls, client.calls); diff != "" {
					t.Fatalf("service configuration and advertisement order (-want +got):\n%s", diff)
				}
				if diff := cmp.Diff(sc, client.applied); diff != "" {
					t.Errorf("applied handlers (-want +got):\n%s", diff)
				}
				if tt.autoAdvertise == "false" {
					return
				}
				if diff := cmp.Diff(sc, client.advertisedConfig); diff != "" {
					t.Errorf("handlers installed before advertisement (-want +got):\n%s", diff)
				}
				mp := client.EditPrefsCalls[0]
				if !mp.AdvertiseServicesSet {
					t.Fatal("advertised services were not set")
				}
				slices.Sort(mp.AdvertiseServices)
				if diff := cmp.Diff([]string{"svc:backend", "svc:frontend"}, mp.AdvertiseServices); diff != "" {
					t.Errorf("advertised services (-want +got):\n%s", diff)
				}
			})
		})
	}
}

func TestWatchServeConfigChangesRetriesHTTPS(t *testing.T) {
	for _, serviceHTTPS := range []bool{false, true} {
		name := "node_https"
		if serviceHTTPS {
			name = "service_https"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("TS_EXPERIMENTAL_SERVICE_AUTO_ADVERTISEMENT", "true")
			path := filepath.Join(t.TempDir(), "serve.json")
			// No certificate-domain placeholder: the file remains identical
			// when HTTPS becomes available, so rejected configs must not be cached.
			sc := &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:backend": {TCP: map[uint16]*ipn.TCPPortHandler{80: {TCPForward: "127.0.0.1:8081"}}},
				},
			}
			httpsTCP := map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}}
			httpsWeb := map[ipn.HostPort]*ipn.WebServerConfig{
				"frontend.tailnet.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Proxy: "http://127.0.0.1:8080"}}},
			}
			if serviceHTTPS {
				sc.Services["svc:frontend"] = &ipn.ServiceConfig{TCP: httpsTCP, Web: httpsWeb}
			} else {
				sc.TCP, sc.Web = httpsTCP, httpsWeb
			}
			b, err := json.Marshal(sc)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var certDomain atomic.Pointer[string]
				certDomain.Store(new(kubetypes.ValueNoHTTPS))
				changed := make(chan bool, 1)
				client := &recordingServeClient{}
				done := make(chan struct{})
				go func() {
					defer close(done)
					watchServeConfigChangesLoop(ctx, changed, &certDomain, client, nil, &settings{ServeConfigPath: path}, nil, nil, nil)
				}()
				changed <- true
				synctest.Wait()
				if len(client.calls) != 0 {
					t.Errorf("rejected HTTPS config must not be applied or advertised; got %v", client.calls)
				}
				certDomain.Store(new("test-node.tailnet.ts.net"))
				changed <- true
				synctest.Wait()
				cancel()
				<-done
				if diff := cmp.Diff([]string{"SetServeConfig", "EditPrefs"}, client.calls); diff != "" {
					t.Fatalf("retry configuration and advertisement order (-want +got):\n%s", diff)
				}
				if diff := cmp.Diff(sc, client.advertisedConfig); diff != "" {
					t.Errorf("handlers installed before advertisement (-want +got):\n%s", diff)
				}
				got := client.EditPrefsCalls[0]
				if !got.AdvertiseServicesSet {
					t.Fatal("retried services were not advertised")
				}
				want := make(map[string]bool)
				for svc := range sc.Services {
					want[svc.String()] = true
				}
				advertised := make(map[string]bool)
				for _, svc := range got.AdvertiseServices {
					advertised[svc] = true
				}
				if diff := cmp.Diff(want, advertised); diff != "" {
					t.Errorf("retried services (-want +got):\n%s", diff)
				}
			})
		})
	}
}

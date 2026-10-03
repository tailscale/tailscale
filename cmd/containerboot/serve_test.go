// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/client/local"
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
			err := updateServeConfig(context.Background(), tt.sc, tt.certDomain, fakeLC)
			if err != nil {
				t.Errorf("updateServeConfig() error = %v", err)
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

// TestWatchServeConfigChangesAdvertisesServices verifies that when the serve
// config file is applied by the watcher, the services it defines are
// advertised. This is the path taken on a restart with existing state, where
// the serve config is unset at startup and so is still empty when the first
// netmap arrives. See https://github.com/tailscale/tailscale/issues/21455.
func TestWatchServeConfigChangesAdvertisesServices(t *testing.T) {
	t.Setenv("TS_EXPERIMENTAL_SERVICE_AUTO_ADVERTISEMENT", "true")
	d := t.TempDir()
	scPath := filepath.Join(d, "serve-config.json")
	sc := &ipn.ServeConfig{
		Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
			"svc:my-service": {
				TCP: map[uint16]*ipn.TCPPortHandler{
					80: {TCPForward: "127.0.0.1:8080"},
				},
			},
		},
	}
	b, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scPath, b, 0644); err != nil {
		t.Fatal(err)
	}

	var gotServices atomic.Pointer[[]string]
	advertised := make(chan []string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/localapi/v0/serve-config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(&ipn.ServeConfig{})
		}
	})
	mux.HandleFunc("/localapi/v0/prefs", func(w http.ResponseWriter, r *http.Request) {
		var mp ipn.MaskedPrefs
		if r.Method == "PATCH" {
			if err := json.NewDecoder(r.Body).Decode(&mp); err != nil {
				t.Errorf("decoding EditPrefs body: %v", err)
			}
			if mp.AdvertiseServicesSet {
				gotServices.Store(&mp.AdvertiseServices)
				// Close the connection after this response so that the
				// client side Close below tells us EditPrefs has
				// received its response.
				w.Header().Set("Connection", "close")
			}
		}
		json.NewEncoder(w).Encode(&mp.Prefs)
	})
	sock := filepath.Join(d, "ts.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lc := &local.Client{
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := new(net.Dialer).DialContext(ctx, "unix", sock)
			if err != nil {
				return nil, err
			}
			return &closeNotifyConn{Conn: c, onClose: func() {
				if svcs := gotServices.Load(); svcs != nil {
					select {
					case advertised <- *svcs:
					default:
					}
				}
			}}, nil
		},
	}
	var certDomain atomic.Pointer[string]
	certDomain.Store(new(string))
	cdChanged := make(chan bool, 1)
	cdChanged <- true
	cfg := &settings{ServeConfigPath: scPath}
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchServeConfigChanges(ctx, cdChanged, &certDomain, lc, nil, cfg, &ipn.ServeConfig{})
	}()

	select {
	case got := <-advertised:
		if diff := cmp.Diff([]string{"svc:my-service"}, got); diff != "" {
			t.Errorf("advertised services mismatch (-want +got):\n%s", diff)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("services from serve config were never advertised")
	}
	cancel()
	<-done
}

type closeNotifyConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.onClose)
	return err
}

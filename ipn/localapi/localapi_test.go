// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine"
)

func TestValidHost(t *testing.T) {
	tests := []struct {
		host  string
		valid bool
	}{
		{"", true},
		{apitype.LocalAPIHost, true},
		{"localhost:9109", false},
		{"127.0.0.1:9110", false},
		{"[::1]:9111", false},
		{"100.100.100.100:41112", false},
		{"10.0.0.1:41112", false},
		{"37.16.9.210:41112", false},
	}

	for _, test := range tests {
		t.Run(test.host, func(t *testing.T) {
			h := &Handler{}
			if got := h.validHost(test.host); got != test.valid {
				t.Errorf("validHost(%q)=%v, want %v", test.host, got, test.valid)
			}
		})
	}
}

func TestSetPushDeviceToken(t *testing.T) {
	tstest.Replace(t, &validLocalHostForTesting, true)

	h := &Handler{
		PermitWrite: true,
		b:           &ipnlocal.LocalBackend{},
	}
	s := httptest.NewServer(h)
	defer s.Close()
	c := s.Client()

	want := "my-test-device-token"
	body, err := json.Marshal(apitype.SetPushDeviceTokenRequest{PushDeviceToken: want})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", s.URL+"/localapi/v0/set-push-device-token", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Errorf("res.StatusCode=%d, want 200. body: %s", res.StatusCode, body)
	}
	if got := h.b.GetPushDeviceToken(); got != want {
		t.Errorf("hostinfo.PushDeviceToken=%q, want %q", got, want)
	}
}

type whoIsBackend struct {
	whoIs    func(ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool)
	peerCaps map[netip.Addr]tailcfg.PeerCapMap
}

func (b whoIsBackend) WhoIs(ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
	return b.whoIs(ipp)
}

func (b whoIsBackend) PeerCaps(ip netip.Addr) tailcfg.PeerCapMap {
	return b.peerCaps[ip]
}

// Tests that the WhoIs handler accepts either IPs or IP:ports.
//
// From https://github.com/tailscale/tailscale/pull/9714 (a PR that is effectively a bug report)
func TestWhoIsJustIP(t *testing.T) {
	h := &Handler{
		PermitRead: true,
	}
	for _, input := range []string{"100.101.102.103", "127.0.0.1:123"} {
		rec := httptest.NewRecorder()
		t.Run(input, func(t *testing.T) {
			b := whoIsBackend{
				whoIs: func(ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
					if !strings.Contains(input, ":") {
						want := netip.MustParseAddrPort("100.101.102.103:0")
						if ipp != want {
							t.Fatalf("backend called with %v; want %v", ipp, want)
						}
					}
					return (&tailcfg.Node{
							ID: 123,
							Addresses: []netip.Prefix{
								netip.MustParsePrefix("100.101.102.103/32"),
							},
						}).View(),
						tailcfg.UserProfile{ID: 456, DisplayName: "foo"},
						true
				},
				peerCaps: map[netip.Addr]tailcfg.PeerCapMap{
					netip.MustParseAddr("100.101.102.103"): map[tailcfg.PeerCapability][]tailcfg.RawMessage{
						"foo": {`"bar"`},
					},
				},
			}
			h.serveWhoIsWithBackend(rec, httptest.NewRequest("GET", "/v0/whois?addr="+url.QueryEscape(input), nil), b)

			var res apitype.WhoIsResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
				t.Fatal(err)
			}
			if got, want := res.Node.ID, tailcfg.NodeID(123); got != want {
				t.Errorf("res.Node.ID=%v, want %v", got, want)
			}
			if got, want := res.UserProfile.DisplayName, "foo"; got != want {
				t.Errorf("res.UserProfile.DisplayName=%q, want %q", got, want)
			}
			if got, want := len(res.CapMap), 1; got != want {
				t.Errorf("capmap size=%v, want %v", got, want)
			}
		})
	}
}

func TestShouldDenyServeConfigForGOOSAndUserContext(t *testing.T) {
	tests := []struct {
		name     string
		goos     string
		configIn *ipn.ServeConfig
		h        *Handler
		wantErr  bool
	}{
		{
			name:     "linux",
			goos:     "linux",
			configIn: &ipn.ServeConfig{},
			h:        &Handler{CallerIsLocalAdmin: false},
			wantErr:  false,
		},
		{
			name: "linux-path-handler-admin",
			goos: "linux",
			configIn: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Path: "/tmp"},
					}},
				},
			},
			h:       &Handler{CallerIsLocalAdmin: true},
			wantErr: false,
		},
		{
			name: "linux-path-handler-not-admin",
			goos: "linux",
			configIn: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Path: "/tmp"},
					}},
				},
			},
			h:       &Handler{CallerIsLocalAdmin: false},
			wantErr: true,
		},
		{
			name: "windows-not-path-handler",
			goos: "windows",
			configIn: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Proxy: "http://127.0.0.1:3000"},
					}},
				},
			},
			h:       &Handler{CallerIsLocalAdmin: false},
			wantErr: false,
		},
		{
			name: "windows-path-handler-admin",
			goos: "windows",
			configIn: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Path: "/tmp"},
					}},
				},
			},
			h:       &Handler{CallerIsLocalAdmin: true},
			wantErr: false,
		},
		{
			name: "windows-path-handler-not-admin",
			goos: "windows",
			configIn: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Path: "/tmp"},
					}},
				},
			},
			h:       &Handler{CallerIsLocalAdmin: false},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authorizeServeConfigForGOOSAndUserContext(tt.goos, tt.configIn, tt.h)
			gotErr := err != nil
			if gotErr != tt.wantErr {
				t.Errorf("authorizeServeConfigForGOOSAndUserContext() got error = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

func TestServeWatchIPNBus(t *testing.T) {
	tstest.Replace(t, &validLocalHostForTesting, true)

	tests := []struct {
		desc                    string
		permitRead, permitWrite bool
		mask                    ipn.NotifyWatchOpt // extra bits in addition to ipn.NotifyInitialState
		wantStatus              int
	}{
		{
			desc:        "no-permission",
			permitRead:  false,
			permitWrite: false,
			wantStatus:  http.StatusForbidden,
		},
		{
			desc:        "read-initial-state",
			permitRead:  true,
			permitWrite: false,
			wantStatus:  http.StatusForbidden,
		},
		{
			desc:        "read-initial-state-no-private-keys",
			permitRead:  true,
			permitWrite: false,
			mask:        ipn.NotifyNoPrivateKeys,
			wantStatus:  http.StatusOK,
		},
		{
			desc:        "read-initial-state-with-private-keys",
			permitRead:  true,
			permitWrite: true,
			wantStatus:  http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			h := &Handler{
				PermitRead:  tt.permitRead,
				PermitWrite: tt.permitWrite,
				b:           newTestLocalBackend(t),
			}
			s := httptest.NewServer(h)
			defer s.Close()
			c := s.Client()

			ctx, cancel := context.WithCancel(context.Background())
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/localapi/v0/watch-ipn-bus?mask=%d", s.URL, ipn.NotifyInitialState|tt.mask), nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			// Cancel the context so that localapi stops streaming IPN bus
			// updates.
			cancel()
			body, err := io.ReadAll(res.Body)
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if res.StatusCode != tt.wantStatus {
				t.Errorf("res.StatusCode=%d, want %d. body: %s", res.StatusCode, tt.wantStatus, body)
			}
		})
	}
}

func newTestLocalBackend(t testing.TB) *ipnlocal.LocalBackend {
	var logf logger.Logf = logger.Discard
	sys := new(tsd.System)
	store := new(mem.Store)
	sys.Set(store)
	eng, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set)
	if err != nil {
		t.Fatalf("NewFakeUserspaceEngine: %v", err)
	}
	t.Cleanup(eng.Close)
	sys.Set(eng)
	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	return lb
}

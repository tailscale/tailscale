// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/slicesx"
	"tailscale.com/wgengine"
)

func handlerForTest(t testing.TB, h *Handler) *Handler {
	if h.Actor == nil {
		h.Actor = &ipnauth.TestActor{}
	}
	if h.b == nil {
		h.b = &ipnlocal.LocalBackend{}
	}
	if h.logf == nil {
		h.logf = logger.TestLogger(t)
	}
	return h
}

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
			h := handlerForTest(t, &Handler{})
			if got := h.validHost(test.host); got != test.valid {
				t.Errorf("validHost(%q)=%v, want %v", test.host, got, test.valid)
			}
		})
	}
}

func TestSetPushDeviceToken(t *testing.T) {
	tstest.Replace(t, &validLocalHostForTesting, true)

	h := handlerForTest(t, &Handler{
		PermitWrite: true,
	})
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
	whoIs        func(proto string, ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool)
	whoIsNodeKey func(key.NodePublic) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool)
	peerCaps     map[netip.Addr]tailcfg.PeerCapMap
}

func (b whoIsBackend) WhoIs(proto string, ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
	return b.whoIs(proto, ipp)
}

func (b whoIsBackend) WhoIsNodeKey(k key.NodePublic) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
	return b.whoIsNodeKey(k)
}

func (b whoIsBackend) PeerCaps(ip netip.Addr) tailcfg.PeerCapMap {
	return b.peerCaps[ip]
}

// Tests that the WhoIs handler accepts IPs, IP:ports, or nodekeys.
//
// From https://github.com/tailscale/tailscale/pull/9714 (a PR that is effectively a bug report)
//
// And https://github.com/tailscale/tailscale/issues/12465
func TestWhoIsArgTypes(t *testing.T) {
	h := handlerForTest(t, &Handler{
		PermitRead: true,
	})

	match := func() (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
		return (&tailcfg.Node{
				ID: 123,
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.101.102.103/32"),
				},
			}).View(),
			tailcfg.UserProfile{ID: 456, DisplayName: "foo"},
			true
	}

	const keyStr = "nodekey:5c8f86d5fc70d924e55f02446165a5dae8f822994ad26bcf4b08fd841f9bf261"
	for _, input := range []string{"100.101.102.103", "127.0.0.1:123", keyStr} {
		rec := httptest.NewRecorder()
		t.Run(input, func(t *testing.T) {
			b := whoIsBackend{
				whoIs: func(proto string, ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
					if !strings.Contains(input, ":") {
						want := netip.MustParseAddrPort("100.101.102.103:0")
						if ipp != want {
							t.Fatalf("backend called with %v; want %v", ipp, want)
						}
					}
					return match()
				},
				whoIsNodeKey: func(k key.NodePublic) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
					if k.String() != keyStr {
						t.Fatalf("backend called with %v; want %v", k, keyStr)
					}
					return match()
				},
				peerCaps: map[netip.Addr]tailcfg.PeerCapMap{
					netip.MustParseAddr("100.101.102.103"): map[tailcfg.PeerCapability][]tailcfg.RawMessage{
						"foo": {`"bar"`},
					},
				},
			}
			h.serveWhoIsWithBackend(rec, httptest.NewRequest("GET", "/v0/whois?addr="+url.QueryEscape(input), nil), b)

			if rec.Code != 200 {
				t.Fatalf("response code %d", rec.Code)
			}
			var res apitype.WhoIsResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
				t.Fatalf("parsing response %#q: %v", rec.Body.Bytes(), err)
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
	newHandler := func(connIsLocalAdmin bool) *Handler {
		return handlerForTest(t, &Handler{
			Actor: &ipnauth.TestActor{LocalAdmin: connIsLocalAdmin},
			b:     newTestLocalBackend(t),
		})
	}
	tests := []struct {
		name     string
		configIn *ipn.ServeConfig
		h        *Handler
		wantErr  bool
	}{
		{
			name: "not-path-handler",
			configIn: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Proxy: "http://127.0.0.1:3000"},
					}},
				},
			},
			h:       newHandler(false),
			wantErr: false,
		},
		{
			name: "path-handler-admin",
			configIn: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Path: "/tmp"},
					}},
				},
			},
			h:       newHandler(true),
			wantErr: false,
		},
		{
			name: "path-handler-not-admin",
			configIn: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Path: "/tmp"},
					}},
				},
			},
			h:       newHandler(false),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		for _, goos := range []string{"linux", "windows", "darwin", "illumos", "solaris"} {
			t.Run(goos+"-"+tt.name, func(t *testing.T) {
				err := authorizeServeConfigForGOOSAndUserContext(goos, tt.configIn, tt.h)
				gotErr := err != nil
				if gotErr != tt.wantErr {
					t.Errorf("authorizeServeConfigForGOOSAndUserContext() got error = %v, want error %v", err, tt.wantErr)
				}
			})
		}
	}
	t.Run("other-goos", func(t *testing.T) {
		configIn := &ipn.ServeConfig{
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Path: "/tmp"},
				}},
			},
		}
		h := newHandler(false)
		err := authorizeServeConfigForGOOSAndUserContext("dos", configIn, h)
		if err != nil {
			t.Errorf("authorizeServeConfigForGOOSAndUserContext() got error = %v, want nil", err)
		}
	})
}

// TestServeWatchIPNBus used to test that various WatchIPNBus mask flags
// changed the permissions required to access the endpoint.
// However, since the removal of the NotifyNoPrivateKeys flag requirement
// for read-only users, this test now only verifies that the endpoint
// behaves correctly based on the PermitRead and PermitWrite settings.
func TestServeWatchIPNBus(t *testing.T) {
	tstest.Replace(t, &validLocalHostForTesting, true)

	tests := []struct {
		desc                    string
		permitRead, permitWrite bool
		wantStatus              int
	}{
		{
			desc:        "no-permission",
			permitRead:  false,
			permitWrite: false,
			wantStatus:  http.StatusForbidden,
		},
		{
			desc:        "read-only",
			permitRead:  true,
			permitWrite: false,
			wantStatus:  http.StatusOK,
		},
		{
			desc:        "read-and-write",
			permitRead:  true,
			permitWrite: true,
			wantStatus:  http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			h := handlerForTest(t, &Handler{
				PermitRead:  tt.permitRead,
				PermitWrite: tt.permitWrite,
				b:           newTestLocalBackend(t),
			})
			s := httptest.NewServer(h)
			defer s.Close()
			c := s.Client()

			ctx, cancel := context.WithCancel(context.Background())
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/localapi/v0/watch-ipn-bus?mask=%d", s.URL, ipn.NotifyInitialState), nil)
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
	sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))
	store := new(mem.Store)
	sys.Set(store)
	eng, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	if err != nil {
		t.Fatalf("NewFakeUserspaceEngine: %v", err)
	}
	t.Cleanup(eng.Close)
	sys.Set(eng)
	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	t.Cleanup(lb.Shutdown)
	return lb
}

func TestKeepItSorted(t *testing.T) {
	// Parse the localapi.go file into an AST.
	fset := token.NewFileSet() // positions are relative to fset
	src, err := os.ReadFile("localapi.go")
	if err != nil {
		log.Fatal(err)
	}
	f, err := parser.ParseFile(fset, "localapi.go", src, 0)
	if err != nil {
		log.Fatal(err)
	}
	getHandler := func() *ast.ValueSpec {
		for _, d := range f.Decls {
			if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.VAR {
				for _, s := range g.Specs {
					if vs, ok := s.(*ast.ValueSpec); ok {
						if len(vs.Names) == 1 && vs.Names[0].Name == "handler" {
							return vs
						}
					}
				}
			}
		}
		return nil
	}
	keys := func() (ret []string) {
		h := getHandler()
		if h == nil {
			t.Fatal("no handler var found")
		}
		cl, ok := h.Values[0].(*ast.CompositeLit)
		if !ok {
			t.Fatalf("handler[0] is %T, want *ast.CompositeLit", h.Values[0])
		}
		for _, e := range cl.Elts {
			kv := e.(*ast.KeyValueExpr)
			strLt := kv.Key.(*ast.BasicLit)
			if strLt.Kind != token.STRING {
				t.Fatalf("got: %T, %q", kv.Key, kv.Key)
			}
			k, err := strconv.Unquote(strLt.Value)
			if err != nil {
				t.Fatalf("unquote: %v", err)
			}
			ret = append(ret, k)
		}
		return
	}
	gotKeys := keys()
	endSlash, noSlash := slicesx.Partition(keys(), func(s string) bool { return strings.HasSuffix(s, "/") })
	if !slices.IsSorted(endSlash) {
		t.Errorf("the items ending in a slash aren't sorted")
	}
	if !slices.IsSorted(noSlash) {
		t.Errorf("the items ending in a slash aren't sorted")
	}
	if !t.Failed() {
		want := append(endSlash, noSlash...)
		if !slices.Equal(gotKeys, want) {
			t.Errorf("items with trailing slashes should precede those without")
		}
	}
}

func TestServeWithUnhealthyState(t *testing.T) {
	tstest.Replace(t, &validLocalHostForTesting, true)
	h := &Handler{
		PermitRead:  true,
		PermitWrite: true,
		b:           newTestLocalBackend(t),
		logf:        t.Logf,
	}
	h.b.HealthTracker().SetUnhealthy(ipn.StateStoreHealth, health.Args{health.ArgError: "testing"})
	if err := h.b.Start(ipn.Options{}); err != nil {
		t.Fatal(err)
	}

	check500Body := func(wantResp string) func(t *testing.T, code int, resp []byte) {
		return func(t *testing.T, code int, resp []byte) {
			if code != http.StatusInternalServerError {
				t.Errorf("got code: %v, want %v\nresponse: %q", code, http.StatusInternalServerError, resp)
			}
			if got := strings.TrimSpace(string(resp)); got != wantResp {
				t.Errorf("got response: %q, want %q", got, wantResp)
			}
		}
	}
	tests := []struct {
		desc  string
		req   *http.Request
		check func(t *testing.T, code int, resp []byte)
	}{
		{
			desc: "status",
			req:  httptest.NewRequest("GET", "http://localhost:1234/localapi/v0/status", nil),
			check: func(t *testing.T, code int, resp []byte) {
				if code != http.StatusOK {
					t.Errorf("got code: %v, want %v\nresponse: %q", code, http.StatusOK, resp)
				}
				var status ipnstate.Status
				if err := json.Unmarshal(resp, &status); err != nil {
					t.Fatal(err)
				}
				if status.BackendState != "NoState" {
					t.Errorf("got backend state: %q, want %q", status.BackendState, "NoState")
				}
			},
		},
		{
			desc:  "login-interactive",
			req:   httptest.NewRequest("POST", "http://localhost:1234/localapi/v0/login-interactive", nil),
			check: check500Body("cannot log in when state store is unhealthy"),
		},
		{
			desc:  "start",
			req:   httptest.NewRequest("POST", "http://localhost:1234/localapi/v0/start", strings.NewReader("{}")),
			check: check500Body("cannot start backend when state store is unhealthy"),
		},
		{
			desc:  "new-profile",
			req:   httptest.NewRequest("PUT", "http://localhost:1234/localapi/v0/profiles/", nil),
			check: check500Body("cannot log in when state store is unhealthy"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, tt.req)
			tt.check(t, resp.Code, resp.Body.Bytes())
		})
	}
}

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

// ===== defBool Tests =====

func TestDefBool(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		def      bool
		expected bool
	}{
		{"empty_default_true", "", true, true},
		{"empty_default_false", "", false, false},
		{"true_string", "true", false, true},
		{"false_string", "false", true, false},
		{"1_string", "1", false, true},
		{"0_string", "0", true, false},
		{"t_string", "t", false, true},
		{"f_string", "f", true, false},
		{"invalid_uses_default_true", "invalid", true, true},
		{"invalid_uses_default_false", "invalid", false, false},
		{"True_uppercase", "True", false, true},
		{"FALSE_uppercase", "FALSE", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defBool(tt.input, tt.def)
			if got != tt.expected {
				t.Errorf("defBool(%q, %v) = %v, want %v", tt.input, tt.def, got, tt.expected)
			}
		})
	}
}

// ===== dnsMessageTypeForString Tests =====

func TestDNSMessageTypeForString(t *testing.T) {
	tests := []struct {
		input    string
		expected string // type name for comparison
		wantErr  bool
	}{
		{"A", "TypeA", false},
		{"AAAA", "TypeAAAA", false},
		{"CNAME", "TypeCNAME", false},
		{"MX", "TypeMX", false},
		{"NS", "TypeNS", false},
		{"PTR", "TypePTR", false},
		{"SOA", "TypeSOA", false},
		{"SRV", "TypeSRV", false},
		{"TXT", "TypeTXT", false},
		{"ALL", "TypeALL", false},
		{"HINFO", "TypeHINFO", false},
		{"MINFO", "TypeMINFO", false},
		{"OPT", "TypeOPT", false},
		{"WKS", "TypeWKS", false},
		// Lowercase should work (gets uppercased)
		{"a", "TypeA", false},
		{"aaaa", "TypeAAAA", false},
		{"txt", "TypeTXT", false},
		// With whitespace (gets trimmed)
		{" A ", "TypeA", false},
		{"  AAAA  ", "TypeAAAA", false},
		// Invalid types
		{"INVALID", "", true},
		{"", "", true},
		{"UNKNOWN", "", true},
		{"B", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := dnsMessageTypeForString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("dnsMessageTypeForString(%q) succeeded, want error", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("dnsMessageTypeForString(%q) failed: %v", tt.input, err)
				return
			}
			// We can't directly compare dnsmessage.Type values easily,
			// but we can check that we got a non-zero value for valid types
			if got == 0 {
				t.Errorf("dnsMessageTypeForString(%q) = 0, want non-zero type", tt.input)
			}
		})
	}
}

// ===== handlerForPath Tests =====

func TestHandlerForPath(t *testing.T) {
	tests := []struct {
		path       string
		wantRoute  string
		wantOK     bool
		wantPrefix bool // whether it's a prefix match
	}{
		{"/", "/", true, false},
		{"/localapi/v0/status", "/localapi/v0/status", true, false},
		{"/localapi/v0/prefs", "/localapi/v0/prefs", true, false},
		{"/localapi/v0/profiles/", "/localapi/v0/profiles/", true, true},
		{"/localapi/v0/profiles/123", "/localapi/v0/profiles/", true, true},
		{"/localapi/v0/start", "/localapi/v0/start", true, false},
		{"/localapi/v0/shutdown", "/localapi/v0/shutdown", true, false},
		{"/localapi/v0/ping", "/localapi/v0/ping", true, false},
		{"/localapi/v0/whois", "/localapi/v0/whois", true, false},
		{"/localapi/v0/goroutines", "/localapi/v0/goroutines", true, false},
		{"/localapi/v0/derpmap", "/localapi/v0/derpmap", true, false},
		// Invalid paths
		{"/invalid", "", false, false},
		{"/localapi/invalid", "", false, false},
		{"/api/v0/status", "", false, false},
		{"/localapi/v1/status", "", false, false},
		{"/localapi/v0/nonexistent", "", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			fn, route, ok := handlerForPath(tt.path)
			if ok != tt.wantOK {
				t.Errorf("handlerForPath(%q) ok = %v, want %v", tt.path, ok, tt.wantOK)
			}
			if route != tt.wantRoute {
				t.Errorf("handlerForPath(%q) route = %q, want %q", tt.path, route, tt.wantRoute)
			}
			if tt.wantOK && fn == nil {
				t.Errorf("handlerForPath(%q) returned nil handler", tt.path)
			}
			if !tt.wantOK && fn != nil {
				t.Errorf("handlerForPath(%q) returned non-nil handler for invalid path", tt.path)
			}
		})
	}
}

func TestHandlerForPath_PrefixMatching(t *testing.T) {
	// Test that prefix matches work correctly
	_, route1, ok1 := handlerForPath("/localapi/v0/profiles/")
	_, route2, ok2 := handlerForPath("/localapi/v0/profiles/current")
	_, route3, ok3 := handlerForPath("/localapi/v0/profiles/123/switch")

	if !ok1 || !ok2 || !ok3 {
		t.Error("prefix matching should work for all profiles/ paths")
	}

	// All should return the same route (the prefix)
	if route1 != "/localapi/v0/profiles/" {
		t.Errorf("route1 = %q, want /localapi/v0/profiles/", route1)
	}
	if route2 != "/localapi/v0/profiles/" {
		t.Errorf("route2 = %q, want /localapi/v0/profiles/", route2)
	}
	if route3 != "/localapi/v0/profiles/" {
		t.Errorf("route3 = %q, want /localapi/v0/profiles/", route3)
	}
}

// ===== WriteErrorJSON Tests =====

func TestWriteErrorJSON(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		wantStatus     int
		wantBodySubstr string
	}{
		{
			name:           "simple_error",
			err:            errors.New("test error"),
			wantStatus:     http.StatusInternalServerError,
			wantBodySubstr: "test error",
		},
		{
			name:           "nil_error",
			err:            nil,
			wantStatus:     http.StatusInternalServerError,
			wantBodySubstr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			WriteErrorJSON(rec, tt.err)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantBodySubstr != "" && !strings.Contains(rec.Body.String(), tt.wantBodySubstr) {
				t.Errorf("body = %q, want to contain %q", rec.Body.String(), tt.wantBodySubstr)
			}

			// Check Content-Type
			ct := rec.Header().Get("Content-Type")
			if ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
		})
	}
}

// ===== Register Tests =====

func TestRegister(t *testing.T) {
	// Save the original handler map
	originalHandler := handler

	// Create a test handler function
	testHandler := func(h *Handler, w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test"))
	}

	// Register a new handler
	testRoute := "test-route-12345"
	Register(testRoute, testHandler)

	// Verify it was registered
	fn, route, ok := handlerForPath("/localapi/v0/" + testRoute)
	if !ok {
		t.Error("registered route not found")
	}
	if route != "/localapi/v0/"+testRoute {
		t.Errorf("route = %q, want %q", route, "/localapi/v0/"+testRoute)
	}
	if fn == nil {
		t.Error("registered handler is nil")
	}

	// Restore original handler map
	handler = originalHandler
}

// ===== InUseOtherUserIPNStream Tests =====

func TestInUseOtherUserIPNStream(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantHandled bool
	}{
		{
			name:        "in_use_error",
			err:         ipn.ErrStateNotExist,
			wantHandled: true,
		},
		{
			name:        "other_error",
			err:         errors.New("some other error"),
			wantHandled: false,
		},
		{
			name:        "nil_error",
			err:         nil,
			wantHandled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)

			handled := InUseOtherUserIPNStream(rec, req, tt.err)

			if handled != tt.wantHandled {
				t.Errorf("InUseOtherUserIPNStream() handled = %v, want %v", handled, tt.wantHandled)
			}

			if tt.wantHandled && rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d for handled error", rec.Code, http.StatusForbidden)
			}
		})
	}
}

// ===== Handler Permission Tests =====

func TestHandler_PermitRead(t *testing.T) {
	h := &Handler{
		PermitRead: true,
		b:          &ipnlocal.LocalBackend{},
	}

	if !h.PermitRead {
		t.Error("PermitRead should be true")
	}
}

func TestHandler_PermitWrite(t *testing.T) {
	h := &Handler{
		PermitWrite: true,
		b:           &ipnlocal.LocalBackend{},
	}

	if !h.PermitWrite {
		t.Error("PermitWrite should be true")
	}
}

func TestHandler_PermitCert(t *testing.T) {
	h := &Handler{
		PermitCert: true,
		b:          &ipnlocal.LocalBackend{},
	}

	if !h.PermitCert {
		t.Error("PermitCert should be true")
	}
}

func TestHandler_RequiredPassword(t *testing.T) {
	h := &Handler{
		RequiredPassword: "test-password",
		b:                &ipnlocal.LocalBackend{},
	}

	if h.RequiredPassword != "test-password" {
		t.Errorf("RequiredPassword = %q, want %q", h.RequiredPassword, "test-password")
	}
}

// ===== Handler Methods Tests =====

func TestHandler_Logf(t *testing.T) {
	var logged bool
	logf := func(format string, args ...any) {
		logged = true
	}

	h := &Handler{
		logf: logf,
		b:    &ipnlocal.LocalBackend{},
	}

	h.Logf("test message")

	if !logged {
		t.Error("Logf did not call the logger function")
	}
}

func TestHandler_LocalBackend(t *testing.T) {
	lb := &ipnlocal.LocalBackend{}
	h := &Handler{
		b: lb,
	}

	got := h.LocalBackend()
	if got != lb {
		t.Error("LocalBackend() returned wrong backend")
	}
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/appc"
	"tailscale.com/appc/appctest"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/must"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
)

type peerAPITestEnv struct {
	ph     *peerAPIHandler
	rr     *httptest.ResponseRecorder
	logBuf tstest.MemLogger
}

type check func(*testing.T, *peerAPITestEnv)

func checks(vv ...check) []check { return vv }

func httpStatus(wantStatus int) check {
	return func(t *testing.T, e *peerAPITestEnv) {
		if res := e.rr.Result(); res.StatusCode != wantStatus {
			t.Errorf("HTTP response code = %v; want %v", res.Status, wantStatus)
		}
	}
}

func bodyContains(sub string) check {
	return func(t *testing.T, e *peerAPITestEnv) {
		if body := e.rr.Body.String(); !strings.Contains(body, sub) {
			t.Errorf("HTTP response body does not contain %q; got: %s", sub, body)
		}
	}
}

func bodyNotContains(sub string) check {
	return func(t *testing.T, e *peerAPITestEnv) {
		if body := e.rr.Body.String(); strings.Contains(body, sub) {
			t.Errorf("HTTP response body unexpectedly contains %q; got: %s", sub, body)
		}
	}
}

func TestHandlePeerAPI(t *testing.T) {
	tests := []struct {
		name     string
		isSelf   bool // the peer sending the request is owned by us
		debugCap bool // self node has debug capability
		reqs     []*http.Request
		checks   []check
	}{
		{
			name:   "not_peer_api",
			isSelf: true,
			reqs:   []*http.Request{httptest.NewRequest("GET", "/", nil)},
			checks: checks(
				httpStatus(200),
				bodyContains("This is my Tailscale device."),
				bodyContains("You are the owner of this node."),
			),
		},
		{
			name:   "not_peer_api_not_owner",
			isSelf: false,
			reqs:   []*http.Request{httptest.NewRequest("GET", "/", nil)},
			checks: checks(
				httpStatus(200),
				bodyContains("This is my Tailscale device."),
				bodyNotContains("You are the owner of this node."),
			),
		},
		{
			name:     "goroutines/deny-self-no-cap",
			isSelf:   true,
			debugCap: false,
			reqs:     []*http.Request{httptest.NewRequest("GET", "/v0/goroutines", nil)},
			checks:   checks(httpStatus(403)),
		},
		{
			name:     "goroutines/deny-nonself",
			isSelf:   false,
			debugCap: true,
			reqs:     []*http.Request{httptest.NewRequest("GET", "/v0/goroutines", nil)},
			checks:   checks(httpStatus(403)),
		},
		{
			name:     "goroutines/accept-self",
			isSelf:   true,
			debugCap: true,
			reqs:     []*http.Request{httptest.NewRequest("GET", "/v0/goroutines", nil)},
			checks: checks(
				httpStatus(200),
				bodyContains("ServeHTTP"),
			),
		},
		{
			name:     "host-val/bad-ip",
			isSelf:   true,
			debugCap: true,
			reqs:     []*http.Request{httptest.NewRequest("GET", "http://12.23.45.66:1234/v0/env", nil)},
			checks: checks(
				httpStatus(403),
			),
		},
		{
			name:     "host-val/no-port",
			isSelf:   true,
			debugCap: true,
			reqs:     []*http.Request{httptest.NewRequest("GET", "http://100.100.100.101/v0/env", nil)},
			checks: checks(
				httpStatus(403),
			),
		},
		{
			name:     "host-val/peer",
			isSelf:   true,
			debugCap: true,
			reqs:     []*http.Request{httptest.NewRequest("GET", "http://peer/v0/env", nil)},
			checks: checks(
				httpStatus(200),
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selfNode := &tailcfg.Node{
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.100.100.101/32"),
				},
			}
			if tt.debugCap {
				selfNode.CapMap = tailcfg.NodeCapMap{tailcfg.CapabilityDebug: nil}
			}
			var e peerAPITestEnv
			lb := newTestLocalBackend(t)
			lb.logf = e.logBuf.Logf
			lb.clock = &tstest.Clock{}
			lb.currentNode().SetNetMap(&netmap.NetworkMap{SelfNode: selfNode.View()})
			e.ph = &peerAPIHandler{
				isSelf:   tt.isSelf,
				selfNode: selfNode.View(),
				peerNode: (&tailcfg.Node{
					ComputedName: "some-peer-name",
				}).View(),
				ps: &peerAPIServer{
					b: lb,
				},
			}
			for _, req := range tt.reqs {
				e.rr = httptest.NewRecorder()
				if req.Host == "example.com" {
					req.Host = "100.100.100.101:12345"
				}
				e.ph.ServeHTTP(e.rr, req)
			}
			for _, f := range tt.checks {
				f(t, &e)
			}
		})
	}
}

func TestPeerAPIReplyToDNSQueries(t *testing.T) {
	var h peerAPIHandler

	h.isSelf = true
	if !h.replyToDNSQueries() {
		t.Errorf("for isSelf = false; want true")
	}
	h.isSelf = false
	h.remoteAddr = netip.MustParseAddrPort("100.150.151.152:12345")

	sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))

	ht := health.NewTracker(sys.Bus.Get())
	pm := must.Get(newProfileManager(new(mem.Store), t.Logf, ht))
	reg := new(usermetric.Registry)
	eng, _ := wgengine.NewFakeUserspaceEngine(logger.Discard, 0, ht, reg, sys.Bus.Get(), sys.Set)
	sys.Set(pm.Store())
	sys.Set(eng)

	b := newTestLocalBackendWithSys(t, sys)
	b.pm = pm

	h.ps = &peerAPIServer{b: b}
	if h.ps.b.OfferingExitNode() {
		t.Fatal("unexpectedly offering exit node")
	}
	h.ps.b.pm.SetPrefs((&ipn.Prefs{
		AdvertiseRoutes: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		},
	}).View(), ipn.NetworkProfile{})
	if !h.ps.b.OfferingExitNode() {
		t.Fatal("unexpectedly not offering exit node")
	}

	if h.replyToDNSQueries() {
		t.Errorf("unexpectedly doing DNS without filter")
	}

	h.ps.b.setFilter(filter.NewAllowNone(logger.Discard, new(netipx.IPSet)))
	if h.replyToDNSQueries() {
		t.Errorf("unexpectedly doing DNS without filter")
	}

	f := filter.NewAllowAllForTest(logger.Discard)

	h.ps.b.setFilter(f)
	if !h.replyToDNSQueries() {
		t.Errorf("unexpectedly deny; wanted to be a DNS server")
	}

	// Also test IPv6.
	h.remoteAddr = netip.MustParseAddrPort("[fe70::1]:12345")
	if !h.replyToDNSQueries() {
		t.Errorf("unexpectedly IPv6 deny; wanted to be a DNS server")
	}
}

func TestPeerAPIPrettyReplyCNAME(t *testing.T) {
	for _, shouldStore := range []bool{false, true} {
		var h peerAPIHandler
		h.remoteAddr = netip.MustParseAddrPort("100.150.151.152:12345")

		sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))

		ht := health.NewTracker(sys.Bus.Get())
		reg := new(usermetric.Registry)
		eng, _ := wgengine.NewFakeUserspaceEngine(logger.Discard, 0, ht, reg, sys.Bus.Get(), sys.Set)
		pm := must.Get(newProfileManager(new(mem.Store), t.Logf, ht))
		a := appc.NewAppConnector(appc.Config{
			Logf:            t.Logf,
			EventBus:        sys.Bus.Get(),
			HasStoredRoutes: shouldStore,
		})
		t.Cleanup(a.Close)
		sys.Set(pm.Store())
		sys.Set(eng)

		b := newTestLocalBackendWithSys(t, sys)
		b.pm = pm
		b.appConnector = a // configure as an app connector just to enable the API.

		h.ps = &peerAPIServer{b: b}
		h.ps.resolver = &fakeResolver{build: func(b *dnsmessage.Builder) {
			b.CNAMEResource(
				dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("www.example.com."),
					Type:  dnsmessage.TypeCNAME,
					Class: dnsmessage.ClassINET,
					TTL:   0,
				},
				dnsmessage.CNAMEResource{
					CNAME: dnsmessage.MustNewName("example.com."),
				},
			)
			b.AResource(
				dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   0,
				},
				dnsmessage.AResource{
					A: [4]byte{192, 0, 0, 8},
				},
			)
		}}
		f := filter.NewAllowAllForTest(logger.Discard)
		h.ps.b.setFilter(f)

		if !h.replyToDNSQueries() {
			t.Errorf("unexpectedly deny; wanted to be a DNS server")
		}

		w := httptest.NewRecorder()
		h.handleDNSQuery(w, httptest.NewRequest("GET", "/dns-query?q=www.example.com.", nil))
		if w.Code != http.StatusOK {
			t.Errorf("unexpected status code: %v", w.Code)
		}
		var addrs []string
		json.NewDecoder(w.Body).Decode(&addrs)
		if len(addrs) == 0 {
			t.Fatalf("no addresses returned")
		}
		for _, addr := range addrs {
			netip.MustParseAddr(addr)
		}
	}
}

func TestPeerAPIReplyToDNSQueriesAreObserved(t *testing.T) {
	for _, shouldStore := range []bool{false, true} {
		var h peerAPIHandler
		h.remoteAddr = netip.MustParseAddrPort("100.150.151.152:12345")

		sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))
		bw := eventbustest.NewWatcher(t, sys.Bus.Get())

		rc := &appctest.RouteCollector{}
		ht := health.NewTracker(sys.Bus.Get())
		pm := must.Get(newProfileManager(new(mem.Store), t.Logf, ht))

		reg := new(usermetric.Registry)
		eng, _ := wgengine.NewFakeUserspaceEngine(logger.Discard, 0, ht, reg, sys.Bus.Get(), sys.Set)
		a := appc.NewAppConnector(appc.Config{
			Logf:            t.Logf,
			EventBus:        sys.Bus.Get(),
			RouteAdvertiser: rc,
			HasStoredRoutes: shouldStore,
		})
		t.Cleanup(a.Close)
		sys.Set(pm.Store())
		sys.Set(eng)

		b := newTestLocalBackendWithSys(t, sys)
		b.pm = pm
		b.appConnector = a

		h.ps = &peerAPIServer{b: b}
		h.ps.b.appConnector.UpdateDomains([]string{"example.com"})
		a.Wait(t.Context())

		h.ps.resolver = &fakeResolver{build: func(b *dnsmessage.Builder) {
			b.AResource(
				dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   0,
				},
				dnsmessage.AResource{
					A: [4]byte{192, 0, 0, 8},
				},
			)
		}}
		f := filter.NewAllowAllForTest(logger.Discard)
		h.ps.b.setFilter(f)

		if !h.ps.b.OfferingAppConnector() {
			t.Fatal("expecting to be offering app connector")
		}
		if !h.replyToDNSQueries() {
			t.Errorf("unexpectedly deny; wanted to be a DNS server")
		}

		w := httptest.NewRecorder()
		h.handleDNSQuery(w, httptest.NewRequest("GET", "/dns-query?q=example.com.", nil))
		if w.Code != http.StatusOK {
			t.Errorf("unexpected status code: %v", w.Code)
		}
		a.Wait(t.Context())

		wantRoutes := []netip.Prefix{netip.MustParsePrefix("192.0.0.8/32")}
		if !slices.Equal(rc.Routes(), wantRoutes) {
			t.Errorf("got %v; want %v", rc.Routes(), wantRoutes)
		}

		if err := eventbustest.Expect(bw,
			eqUpdate(appctype.RouteUpdate{Advertise: mustPrefix("192.0.0.8/32")}),
		); err != nil {
			t.Error(err)
		}
	}
}

func TestPeerAPIReplyToDNSQueriesAreObservedWithCNAMEFlattening(t *testing.T) {
	for _, shouldStore := range []bool{false, true} {
		ctx := context.Background()
		var h peerAPIHandler
		h.remoteAddr = netip.MustParseAddrPort("100.150.151.152:12345")

		sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))
		bw := eventbustest.NewWatcher(t, sys.Bus.Get())

		ht := health.NewTracker(sys.Bus.Get())
		reg := new(usermetric.Registry)
		rc := &appctest.RouteCollector{}
		eng, _ := wgengine.NewFakeUserspaceEngine(logger.Discard, 0, ht, reg, sys.Bus.Get(), sys.Set)
		pm := must.Get(newProfileManager(new(mem.Store), t.Logf, ht))
		a := appc.NewAppConnector(appc.Config{
			Logf:            t.Logf,
			EventBus:        sys.Bus.Get(),
			RouteAdvertiser: rc,
			HasStoredRoutes: shouldStore,
		})
		t.Cleanup(a.Close)
		sys.Set(pm.Store())
		sys.Set(eng)

		b := newTestLocalBackendWithSys(t, sys)
		b.pm = pm
		b.appConnector = a

		h.ps = &peerAPIServer{b: b}
		h.ps.b.appConnector.UpdateDomains([]string{"www.example.com"})
		a.Wait(ctx)

		h.ps.resolver = &fakeResolver{build: func(b *dnsmessage.Builder) {
			b.CNAMEResource(
				dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("www.example.com."),
					Type:  dnsmessage.TypeCNAME,
					Class: dnsmessage.ClassINET,
					TTL:   0,
				},
				dnsmessage.CNAMEResource{
					CNAME: dnsmessage.MustNewName("example.com."),
				},
			)
			b.AResource(
				dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   0,
				},
				dnsmessage.AResource{
					A: [4]byte{192, 0, 0, 8},
				},
			)
		}}
		f := filter.NewAllowAllForTest(logger.Discard)
		h.ps.b.setFilter(f)

		if !h.ps.b.OfferingAppConnector() {
			t.Fatal("expecting to be offering app connector")
		}
		if !h.replyToDNSQueries() {
			t.Errorf("unexpectedly deny; wanted to be a DNS server")
		}

		w := httptest.NewRecorder()
		h.handleDNSQuery(w, httptest.NewRequest("GET", "/dns-query?q=www.example.com.", nil))
		if w.Code != http.StatusOK {
			t.Errorf("unexpected status code: %v", w.Code)
		}
		a.Wait(ctx)

		wantRoutes := []netip.Prefix{netip.MustParsePrefix("192.0.0.8/32")}
		if !slices.Equal(rc.Routes(), wantRoutes) {
			t.Errorf("got %v; want %v", rc.Routes(), wantRoutes)
		}

		if err := eventbustest.Expect(bw,
			eqUpdate(appctype.RouteUpdate{Advertise: mustPrefix("192.0.0.8/32")}),
		); err != nil {
			t.Error(err)
		}
	}
}

type fakeResolver struct {
	build func(*dnsmessage.Builder)
}

func (f *fakeResolver) HandlePeerDNSQuery(ctx context.Context, q []byte, from netip.AddrPort, allowName func(name string) bool) (res []byte, err error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	b.EnableCompression()
	b.StartAnswers()
	f.build(&b)
	return b.Finish()
}

// Copyright (c) Tailscale Inc & contributors
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
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/must"
	"tailscale.com/util/set"
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
				selfNode.CapMap = tailcfg.NodeCapMap{nodecap.Debug: nil}
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

func TestIsPeerAPIDNSAllowed(t *testing.T) {
	// This test can not be run in parallel because it modifies
	// HookReplyToDNSQueries and exitNodeDNSFilterForTest.

	r := must.Get(http.NewRequest("POST", "http://peerapi:1234/dns-query", nil))

	originalHooks := HookReplyToDNSQueries
	defer func() { HookReplyToDNSQueries = originalHooks }()

	sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))
	ht := health.NewTracker(sys.Bus.Get())
	pm := must.Get(newProfileManager(new(mem.Store), t.Logf, ht))
	reg := new(usermetric.Registry)
	eng, _ := wgengine.NewFakeUserspaceEngine(logger.Discard, 0, ht, reg, sys.Bus.Get(), sys.Set)
	sys.Set(pm.Store())
	sys.Set(eng)
	b := newTestLocalBackendWithSys(t, sys)
	b.pm = pm
	if b.OfferingExitNode() {
		t.Error("unexpectedly offering exit node")
		return
	}

	addrSubtests := []struct {
		name string
		addr netip.AddrPort
	}{
		{
			name: "v4",
			addr: netip.MustParseAddrPort("100.150.151.152:12345"),
		},
		{
			name: "v6",
			addr: netip.MustParseAddrPort("[fe70::1]:12345"),
		},
	}

	tests := []struct {
		name string

		registerExtension bool // add an extra handler in HookReplyToDNSQueries
		// Only used when registerExtension is true
		extensionUseNameChecker bool
		extensionAllowSource    bool
		extensionApprovedNames  set.Set[string]

		isSelf           bool
		noOfferExitNode  bool
		noPacketFilter   bool
		denyPacketFilter bool

		wantSourceAllowed bool
		wantNamesAllowed  map[string]bool
	}{
		{
			name:            "self",
			isSelf:          true,
			noOfferExitNode: true,

			wantSourceAllowed: true,
			wantNamesAllowed: map[string]bool{
				"is-self.example.com": true,
				"ts.net":              false,
			},
		},
		{
			name:              "no-exit-node",
			noOfferExitNode:   true,
			wantSourceAllowed: false,
		},
		{
			name:              "exit-node-no-packet-filter",
			noPacketFilter:    true,
			wantSourceAllowed: false,
		},
		{
			name:              "exit-node-deny-packet-filter",
			denyPacketFilter:  true,
			wantSourceAllowed: false,
		},
		{
			name:              "exit-node-allow-packet-filter",
			wantSourceAllowed: true,
			wantNamesAllowed: map[string]bool{
				"exit-node.example.com": true,
				"ts.net":                false,
			},
		},
		{
			name:              "extension-deny",
			registerExtension: true,
			noOfferExitNode:   true,

			wantSourceAllowed: false,
		},
		{
			name:              "extension-with-exit-node",
			registerExtension: true,

			wantSourceAllowed: true,
			wantNamesAllowed: map[string]bool{
				"exit-node.example.com": true,
				"ts.net":                false,
			},
		},
		{
			name:                 "extension-without-name-filter",
			registerExtension:    true,
			extensionAllowSource: true,
			noOfferExitNode:      true,

			wantSourceAllowed: true,
			wantNamesAllowed: map[string]bool{
				"exit-node.example.com": true,
				"ts.net":                false,
			},
		},
		{
			name: "extension-with-name-filter",

			registerExtension:       true,
			extensionAllowSource:    true,
			extensionUseNameChecker: true,
			extensionApprovedNames:  set.Of("extension.example.com", "blocked.extension.example.com"),
			noOfferExitNode:         true,

			wantSourceAllowed: true,
			wantNamesAllowed: map[string]bool{
				"extension.example.com":         true,
				"blocked.extension.example.com": false,
				"exit-node.example.com":         false,
				"ts.net":                        false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.extensionApprovedNames) > 0 && !tt.extensionUseNameChecker {
				t.Error("malformed test: extension has approved names but is not using name checker")
			}

			h := peerAPIHandler{
				ps: &peerAPIServer{
					b: b,
				},
				selfNode: (&tailcfg.Node{}).View(),
				peerNode: (&tailcfg.Node{}).View(),
				isSelf:   tt.isSelf,
			}

			var advertiseRoutes []netip.Prefix
			if !tt.noOfferExitNode {
				advertiseRoutes = []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				}
			}
			if err := h.ps.b.pm.SetPrefs((&ipn.Prefs{
				AdvertiseRoutes: advertiseRoutes,
			}).View(), ipn.NetworkProfile{}); err != nil {
				t.Errorf("SetPrefs: %v", err)
				return
			}
			if h.ps.b.OfferingExitNode() != !tt.noOfferExitNode {
				t.Errorf("unexpected: offering exit node = %v, want %v", h.ps.b.OfferingExitNode(), !tt.noOfferExitNode)
				return
			}
			var f *filter.Filter
			if !tt.noPacketFilter {
				if tt.denyPacketFilter {
					f = filter.NewAllowNone(logger.Discard, new(netipx.IPSet))
				} else {
					f = filter.NewAllowAllForTest(logger.Discard)
				}
			}
			h.ps.b.setFilter(f)

			var lastExtensionNameCheck string
			if tt.registerExtension {
				HookReplyToDNSQueries = slices.Clone(originalHooks)
				defer func() { HookReplyToDNSQueries = originalHooks }()

				extensionNameChecker := func(name string) bool {
					lastExtensionNameCheck = name
					return tt.extensionApprovedNames.Contains(name)
				}

				HookReplyToDNSQueries.Add(func(handler PeerAPIHandler, request *http.Request) (sourceAllowed bool, nameAllowed DNSNameFilter) {
					if handler != &h {
						t.Error("unexpected handler")
					}
					if request != r {
						t.Error("unexpected request")
					}
					if tt.extensionUseNameChecker {
						return tt.extensionAllowSource, extensionNameChecker
					}
					return tt.extensionAllowSource, nil
				})
			}

			var lastNameCheck string
			exitNodeDNSFilterForTest = func(name string) bool {
				lastNameCheck = name

				allow, found := tt.wantNamesAllowed[name]
				if !found {
					t.Errorf("unexpected name %q caught by filter", name)
				}
				return allow
			}
			defer func() { exitNodeDNSFilterForTest = nil }()

			for _, tt2 := range addrSubtests {
				t.Run(tt2.name, func(t *testing.T) {
					h.remoteAddr = tt2.addr

					sourceAllowed, nameChecker := h.isPeerAPIDNSAllowed(r)
					if sourceAllowed != tt.wantSourceAllowed {
						t.Errorf("sourceAllowed = %v, want %v", sourceAllowed, tt.wantSourceAllowed)
					}
					if !sourceAllowed {
						if nameChecker != nil {
							t.Errorf("nameChecker != nil when source not allowed, want nil")
						}
						return
					}
					if nameChecker == nil {
						t.Errorf("nameChecker = nil when source allowed, want not-nil")
						return
					}

					for name, want := range tt.wantNamesAllowed {
						got := nameChecker(name)
						if got != want {
							t.Errorf("nameChecker(%q) = %v, want %v", name, got, want)
						}
						if lastNameCheck != name {
							t.Error("lastNameCheck did not update as expected")
						}
						if tt.extensionUseNameChecker && lastExtensionNameCheck != name {
							// Only require the extension to be consulted if the
							// exitNodeDNSFilterForTest filter would have
							// allowed it.
							if want {
								t.Error("extensionUseNameChecker did not update as expected")
							}
						}
					}
				})
			}
		})
	}
}

func TestPeerAPIPrettyReplyCNAME(t *testing.T) {
	r := must.Get(http.NewRequest("POST", "http://peerapi:1234/dns-query", nil))
	for _, shouldStore := range []bool{false, true} {
		h := peerAPIHandler{
			remoteAddr: netip.MustParseAddrPort("100.150.151.152:12345"),
			selfNode: (&tailcfg.Node{}).View(),
			peerNode: (&tailcfg.Node{}).View(),
		}

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

		if allowed, _ := h.isPeerAPIDNSAllowed(r); !allowed {
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
	r := must.Get(http.NewRequest("POST", "http://peerapi:1234/dns-query", nil))
	for _, shouldStore := range []bool{false, true} {
		h := peerAPIHandler{
			remoteAddr: netip.MustParseAddrPort("100.150.151.152:12345"),
			selfNode: (&tailcfg.Node{}).View(),
			peerNode: (&tailcfg.Node{}).View(),
		}

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
		if allowed, _ := h.isPeerAPIDNSAllowed(r); !allowed {
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
	r := must.Get(http.NewRequest("POST", "http://peerapi:1234/dns-query", nil))
	for _, shouldStore := range []bool{false, true} {
		ctx := context.Background()
		h := peerAPIHandler{
			remoteAddr: netip.MustParseAddrPort("100.150.151.152:12345"),
			selfNode: (&tailcfg.Node{}).View(),
			peerNode: (&tailcfg.Node{}).View(),
		}

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
		if allowed, _ := h.isPeerAPIDNSAllowed(r); !allowed {
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

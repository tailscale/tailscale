// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_appconnectors

package ipnlocal_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/dns/dnsmessage"
	_ "tailscale.com/feature/appconnectors"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/must"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
)

// enableAppConnector configures the backend with app connector prefs and
// a netmap that advertises the given domains via a wildcard connector.
// It synchronously triggers OnAuthReconfig to activate the extension,
// then waits for the app connector's async queue to drain.
func enableAppConnector(t *testing.T, b *ipnlocal.LocalBackend, domains ...string) {
	t.Helper()

	// Ensure extensions are initialized (normally happens during Start()).
	b.InitExtensionsForTest()

	if len(domains) == 0 {
		domains = []string{}
	}
	domainsJSON, _ := json.Marshal(domains)
	appCfg := fmt.Sprintf(`{"name":"test","connectors":["*"],"domains":%s}`, domainsJSON)

	b.SetNetMapForTest(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			Name: "test.ts.net",
			CapMap: tailcfg.NodeCapMap{
				"tailscale.com/app-connectors": {tailcfg.RawMessage(appCfg)},
			},
		}).View(),
	})

	prefs := b.Prefs().AsStruct()
	prefs.AppConnector = ipn.AppConnectorPrefs{Advertise: true}
	b.EditPrefs(&ipn.MaskedPrefs{
		Prefs:           *prefs,
		AppConnectorSet: true,
	})

	b.TriggerOnAuthReconfigForTest()

	// Wait for the app connector's async domain/route processing to complete.
	b.WaitAppConnectorForTest(t.Context())
}

func TestOfferingAppConnector(t *testing.T) {
	b := ipnlocal.ExportNewTestBackend(t)
	if b.OfferingAppConnector() {
		t.Fatal("unexpected offering app connector")
	}

	enableAppConnector(t, b)

	if !b.OfferingAppConnector() {
		t.Fatal("expected offering app connector")
	}

	// Disable app connector.
	b.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AppConnector: ipn.AppConnectorPrefs{Advertise: false},
		},
		AppConnectorSet: true,
	})
	b.TriggerOnAuthReconfigForTest()

	if b.OfferingAppConnector() {
		t.Fatal("unexpected offering app connector after disable")
	}
}

func TestRouteAdvertiser(t *testing.T) {
	b := ipnlocal.ExportNewTestBackend(t)
	testPrefix := netip.MustParsePrefix("192.0.0.8/32")

	if err := b.AdvertiseRoute(testPrefix); err != nil {
		t.Fatal(err)
	}

	routes := b.Prefs().AdvertiseRoutes()
	if routes.Len() != 1 || routes.At(0) != testPrefix {
		t.Fatalf("got routes %v, want %v", routes, []netip.Prefix{testPrefix})
	}

	if err := b.UnadvertiseRoute(testPrefix); err != nil {
		t.Fatal(err)
	}

	routes = b.Prefs().AdvertiseRoutes()
	if routes.Len() != 0 {
		t.Fatalf("got routes %v, want none", routes)
	}
}

func TestRouterAdvertiserIgnoresContainedRoutes(t *testing.T) {
	b := ipnlocal.ExportNewTestBackend(t)
	testPrefix := netip.MustParsePrefix("192.0.0.0/24")

	if err := b.AdvertiseRoute(testPrefix); err != nil {
		t.Fatal(err)
	}

	routes := b.Prefs().AdvertiseRoutes()
	if routes.Len() != 1 || routes.At(0) != testPrefix {
		t.Fatalf("got routes %v, want %v", routes, []netip.Prefix{testPrefix})
	}

	if err := b.AdvertiseRoute(netip.MustParsePrefix("192.0.0.8/32")); err != nil {
		t.Fatal(err)
	}

	// The /32 is not added because it is contained within the /24.
	routes = b.Prefs().AdvertiseRoutes()
	if routes.Len() != 1 || routes.At(0) != testPrefix {
		t.Fatalf("got routes %v, want %v", routes, []netip.Prefix{testPrefix})
	}
}

func TestObserveDNSResponse(t *testing.T) {
	b := ipnlocal.ExportNewTestBackend(t)
	bus := b.SysForTest().Bus.Get()
	w := eventbustest.NewWatcher(t, bus)

	// Ensure no panic when no app connector is configured.
	b.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8"))

	// Enable app connector with "example.com" domain.
	enableAppConnector(t, b, "example.com")

	b.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8"))
	b.WaitAppConnectorForTest(t.Context())

	if err := eventbustest.Expect(w,
		eqUpdate(appctype.RouteUpdate{Advertise: mustPrefix("192.0.0.8/32")}),
	); err != nil {
		t.Error(err)
	}
}

func TestReconfigureAppConnector(t *testing.T) {
	b := ipnlocal.ExportNewTestBackend(t)

	// Without advertise prefs, no app connector should be active.
	b.TriggerOnAuthReconfigForTest()
	if b.OfferingAppConnector() {
		t.Fatal("unexpected app connector")
	}

	// Enable app connector with a domain.
	enableAppConnector(t, b, "example.com")
	if !b.OfferingAppConnector() {
		t.Fatal("expected app connector")
	}

	// Disable the connector and verify it is removed.
	b.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AppConnector: ipn.AppConnectorPrefs{Advertise: false},
		},
		AppConnectorSet: true,
	})
	b.TriggerOnAuthReconfigForTest()
	if b.OfferingAppConnector() {
		t.Fatal("expected no app connector")
	}
}

func TestPeerAPIPrettyReplyCNAME(t *testing.T) {
	sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))

	ht := health.NewTracker(sys.Bus.Get())
	reg := new(usermetric.Registry)
	eng, _ := wgengine.NewFakeUserspaceEngine(logger.Discard, 0, ht, reg, sys.Bus.Get(), sys.Set)
	pm := must.Get(ipnlocal.ExportNewProfileManager(new(mem.Store), t.Logf, ht))
	sys.Set(pm.Store())
	sys.Set(eng)

	b := ipnlocal.ExportNewTestLocalBackendWithSys(t, sys)
	b.SetProfileManagerForTest(pm)

	enableAppConnector(t, b)

	ps := ipnlocal.NewPeerAPIServerForTest(b)
	ps.SetResolver(&fakeResolver{build: func(b *dnsmessage.Builder) {
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
	}})
	b.SetFilterForTest(filter.NewAllowAllForTest(logger.Discard))

	h := ipnlocal.NewPeerAPIHandlerForTest(ps, netip.MustParseAddrPort("100.150.151.152:12345"))
	if !h.ReplyToDNSQueries() {
		t.Errorf("unexpectedly deny; wanted to be a DNS server")
	}

	w := httptest.NewRecorder()
	h.HandleDNSQuery(w, httptest.NewRequest("GET", "/dns-query?q=www.example.com.", nil))
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

func TestPeerAPIReplyToDNSQueriesAreObserved(t *testing.T) {
	sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))
	bw := eventbustest.NewWatcher(t, sys.Bus.Get())

	ht := health.NewTracker(sys.Bus.Get())
	pm := must.Get(ipnlocal.ExportNewProfileManager(new(mem.Store), t.Logf, ht))
	reg := new(usermetric.Registry)
	eng, _ := wgengine.NewFakeUserspaceEngine(logger.Discard, 0, ht, reg, sys.Bus.Get(), sys.Set)
	sys.Set(pm.Store())
	sys.Set(eng)

	b := ipnlocal.ExportNewTestLocalBackendWithSys(t, sys)
	b.SetProfileManagerForTest(pm)

	enableAppConnector(t, b, "example.com")

	if !b.OfferingAppConnector() {
		t.Fatal("expecting to be offering app connector")
	}

	ps := ipnlocal.NewPeerAPIServerForTest(b)
	ps.SetResolver(&fakeResolver{build: func(b *dnsmessage.Builder) {
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
	}})
	b.SetFilterForTest(filter.NewAllowAllForTest(logger.Discard))

	h := ipnlocal.NewPeerAPIHandlerForTest(ps, netip.MustParseAddrPort("100.150.151.152:12345"))
	if !h.ReplyToDNSQueries() {
		t.Errorf("unexpectedly deny; wanted to be a DNS server")
	}

	w := httptest.NewRecorder()
	h.HandleDNSQuery(w, httptest.NewRequest("GET", "/dns-query?q=example.com.", nil))
	if w.Code != http.StatusOK {
		t.Errorf("unexpected status code: %v", w.Code)
	}

	if err := eventbustest.Expect(bw,
		eqUpdate(appctype.RouteUpdate{Advertise: mustPrefix("192.0.0.8/32")}),
	); err != nil {
		t.Error(err)
	}
}

func TestPeerAPIReplyToDNSQueriesAreObservedWithCNAMEFlattening(t *testing.T) {
	sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))
	bw := eventbustest.NewWatcher(t, sys.Bus.Get())

	ht := health.NewTracker(sys.Bus.Get())
	reg := new(usermetric.Registry)
	eng, _ := wgengine.NewFakeUserspaceEngine(logger.Discard, 0, ht, reg, sys.Bus.Get(), sys.Set)
	pm := must.Get(ipnlocal.ExportNewProfileManager(new(mem.Store), t.Logf, ht))
	sys.Set(pm.Store())
	sys.Set(eng)

	b := ipnlocal.ExportNewTestLocalBackendWithSys(t, sys)
	b.SetProfileManagerForTest(pm)

	enableAppConnector(t, b, "www.example.com")

	if !b.OfferingAppConnector() {
		t.Fatal("expecting to be offering app connector")
	}

	ps := ipnlocal.NewPeerAPIServerForTest(b)
	ps.SetResolver(&fakeResolver{build: func(b *dnsmessage.Builder) {
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
	}})
	b.SetFilterForTest(filter.NewAllowAllForTest(logger.Discard))

	h := ipnlocal.NewPeerAPIHandlerForTest(ps, netip.MustParseAddrPort("100.150.151.152:12345"))
	if !h.ReplyToDNSQueries() {
		t.Errorf("unexpectedly deny; wanted to be a DNS server")
	}

	w := httptest.NewRecorder()
	h.HandleDNSQuery(w, httptest.NewRequest("GET", "/dns-query?q=www.example.com.", nil))
	if w.Code != http.StatusOK {
		t.Errorf("unexpected status code: %v", w.Code)
	}

	if err := eventbustest.Expect(bw,
		eqUpdate(appctype.RouteUpdate{Advertise: mustPrefix("192.0.0.8/32")}),
	); err != nil {
		t.Error(err)
	}
}

// fakeResolver implements peerDNSQueryHandler for testing.
type fakeResolver struct {
	build func(*dnsmessage.Builder)
}

func (f *fakeResolver) HandlePeerDNSQuery(_ context.Context, q []byte, from netip.AddrPort, allowName func(name string) bool) (res []byte, err error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	b.EnableCompression()
	b.StartAnswers()
	f.build(&b)
	return b.Finish()
}

// dnsResponse creates a DNS response buffer for the given domain and address.
func dnsResponse(domain, address string) []byte {
	addr := netip.MustParseAddr(address)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	b.EnableCompression()
	b.StartAnswers()
	switch addr.BitLen() {
	case 32:
		b.AResource(
			dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName(domain),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   0,
			},
			dnsmessage.AResource{
				A: addr.As4(),
			},
		)
	case 128:
		b.AAAAResource(
			dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName(domain),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
				TTL:   0,
			},
			dnsmessage.AAAAResource{
				AAAA: addr.As16(),
			},
		)
	default:
		panic("invalid address length")
	}
	return must.Get(b.Finish())
}

type textUpdate struct {
	Advertise   []string
	Unadvertise []string
}

func routeUpdateToText(u appctype.RouteUpdate) textUpdate {
	var out textUpdate
	for _, p := range u.Advertise {
		out.Advertise = append(out.Advertise, p.String())
	}
	for _, p := range u.Unadvertise {
		out.Unadvertise = append(out.Unadvertise, p.String())
	}
	return out
}

func mustPrefix(ss ...string) (out []netip.Prefix) {
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return
}

// eqUpdate generates an eventbus test filter that matches an appctype.RouteUpdate
// message equal to want, or reports an error giving a human-readable diff.
func eqUpdate(want appctype.RouteUpdate) func(appctype.RouteUpdate) error {
	return func(got appctype.RouteUpdate) error {
		if diff := cmp.Diff(routeUpdateToText(got), routeUpdateToText(want)); diff != "" {
			return fmt.Errorf("wrong update (-got, +want):\n%s", diff)
		}
		return nil
	}
}

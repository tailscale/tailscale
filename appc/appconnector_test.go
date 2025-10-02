// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	stdcmp "cmp"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/appc/appctest"
	"tailscale.com/tstest"
	"tailscale.com/types/appctype"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/mak"
	"tailscale.com/util/must"
	"tailscale.com/util/slicesx"
)

func TestUpdateDomains(t *testing.T) {
	ctx := t.Context()
	bus := eventbustest.NewBus(t)
	for _, shouldStore := range []bool{false, true} {
		a := NewAppConnector(Config{
			Logf:            t.Logf,
			EventBus:        bus,
			HasStoredRoutes: shouldStore,
		})
		t.Cleanup(a.Close)

		a.UpdateDomains([]string{"example.com"})
		a.Wait(ctx)
		if got, want := a.Domains().AsSlice(), []string{"example.com"}; !slices.Equal(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}

		addr := netip.MustParseAddr("192.0.0.8")
		a.domains["example.com"] = append(a.domains["example.com"], addr)
		a.UpdateDomains([]string{"example.com"})
		a.Wait(ctx)

		if got, want := a.domains["example.com"], []netip.Addr{addr}; !slices.Equal(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}

		// domains are explicitly downcased on set.
		a.UpdateDomains([]string{"UP.EXAMPLE.COM"})
		a.Wait(ctx)
		if got, want := slicesx.MapKeys(a.domains), []string{"up.example.com"}; !slices.Equal(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}
	}
}

func TestUpdateRoutes(t *testing.T) {
	ctx := t.Context()
	bus := eventbustest.NewBus(t)
	for _, shouldStore := range []bool{false, true} {
		w := eventbustest.NewWatcher(t, bus)
		rc := &appctest.RouteCollector{}
		a := NewAppConnector(Config{
			Logf:            t.Logf,
			EventBus:        bus,
			RouteAdvertiser: rc,
			HasStoredRoutes: shouldStore,
		})
		t.Cleanup(a.Close)

		a.updateDomains([]string{"*.example.com"})

		// This route should be collapsed into the range
		if err := a.ObserveDNSResponse(dnsResponse("a.example.com.", "192.0.2.1")); err != nil {
			t.Errorf("ObserveDNSResponse: %v", err)
		}
		a.Wait(ctx)

		if !slices.Equal(rc.Routes(), []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}) {
			t.Fatalf("got %v, want %v", rc.Routes(), []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")})
		}

		// This route should not be collapsed or removed
		if err := a.ObserveDNSResponse(dnsResponse("b.example.com.", "192.0.0.1")); err != nil {
			t.Errorf("ObserveDNSResponse: %v", err)
		}
		a.Wait(ctx)

		routes := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.0.0.1/32")}
		a.updateRoutes(routes)
		a.Wait(ctx)

		slices.SortFunc(rc.Routes(), prefixCompare)
		rc.SetRoutes(slices.Compact(rc.Routes()))
		slices.SortFunc(routes, prefixCompare)

		// Ensure that the non-matching /32 is preserved, even though it's in the domains table.
		if !slices.EqualFunc(routes, rc.Routes(), prefixEqual) {
			t.Errorf("added routes: got %v, want %v", rc.Routes(), routes)
		}

		// Ensure that the contained /32 is removed, replaced by the /24.
		wantRemoved := []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}
		if !slices.EqualFunc(rc.RemovedRoutes(), wantRemoved, prefixEqual) {
			t.Fatalf("unexpected removed routes: %v", rc.RemovedRoutes())
		}

		if err := eventbustest.Expect(w,
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("192.0.2.1/32")}),
			eventbustest.Type[appctype.RouteInfo](),
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("192.0.0.1/32")}),
			eventbustest.Type[appctype.RouteInfo](),
			eqUpdate(appctype.RouteUpdate{
				Advertise:   prefixes("192.0.0.1/32", "192.0.2.0/24"),
				Unadvertise: prefixes("192.0.2.1/32"),
			}),
			eventbustest.Type[appctype.RouteInfo](),
		); err != nil {
			t.Error(err)
		}
	}
}

func TestUpdateRoutesUnadvertisesContainedRoutes(t *testing.T) {
	ctx := t.Context()
	bus := eventbustest.NewBus(t)
	for _, shouldStore := range []bool{false, true} {
		w := eventbustest.NewWatcher(t, bus)
		rc := &appctest.RouteCollector{}
		a := NewAppConnector(Config{
			Logf:            t.Logf,
			EventBus:        bus,
			RouteAdvertiser: rc,
			HasStoredRoutes: shouldStore,
		})
		t.Cleanup(a.Close)

		mak.Set(&a.domains, "example.com", []netip.Addr{netip.MustParseAddr("192.0.2.1")})
		rc.SetRoutes([]netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")})
		routes := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
		a.updateRoutes(routes)
		a.Wait(ctx)

		if !slices.EqualFunc(routes, rc.Routes(), prefixEqual) {
			t.Fatalf("got %v, want %v", rc.Routes(), routes)
		}

		if err := eventbustest.ExpectExactly(w,
			eqUpdate(appctype.RouteUpdate{
				Advertise:   prefixes("192.0.2.0/24"),
				Unadvertise: prefixes("192.0.2.1/32"),
			}),
			eventbustest.Type[appctype.RouteInfo](),
		); err != nil {
			t.Error(err)
		}
	}
}

func TestDomainRoutes(t *testing.T) {
	bus := eventbustest.NewBus(t)
	for _, shouldStore := range []bool{false, true} {
		w := eventbustest.NewWatcher(t, bus)
		rc := &appctest.RouteCollector{}
		a := NewAppConnector(Config{
			Logf:            t.Logf,
			EventBus:        bus,
			RouteAdvertiser: rc,
			HasStoredRoutes: shouldStore,
		})
		t.Cleanup(a.Close)
		a.updateDomains([]string{"example.com"})
		if err := a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8")); err != nil {
			t.Errorf("ObserveDNSResponse: %v", err)
		}
		a.Wait(t.Context())

		want := map[string][]netip.Addr{
			"example.com": {netip.MustParseAddr("192.0.0.8")},
		}

		if got := a.DomainRoutes(); !reflect.DeepEqual(got, want) {
			t.Fatalf("DomainRoutes: got %v, want %v", got, want)
		}

		if err := eventbustest.ExpectExactly(w,
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("192.0.0.8/32")}),
			eventbustest.Type[appctype.RouteInfo](),
		); err != nil {
			t.Error(err)
		}
	}
}

func TestObserveDNSResponse(t *testing.T) {
	ctx := t.Context()
	bus := eventbustest.NewBus(t)
	for _, shouldStore := range []bool{false, true} {
		w := eventbustest.NewWatcher(t, bus)
		rc := &appctest.RouteCollector{}
		a := NewAppConnector(Config{
			Logf:            t.Logf,
			EventBus:        bus,
			RouteAdvertiser: rc,
			HasStoredRoutes: shouldStore,
		})
		t.Cleanup(a.Close)

		// a has no domains configured, so it should not advertise any routes
		if err := a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8")); err != nil {
			t.Errorf("ObserveDNSResponse: %v", err)
		}
		if got, want := rc.Routes(), ([]netip.Prefix)(nil); !slices.Equal(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}

		wantRoutes := []netip.Prefix{netip.MustParsePrefix("192.0.0.8/32")}

		a.updateDomains([]string{"example.com"})
		if err := a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8")); err != nil {
			t.Errorf("ObserveDNSResponse: %v", err)
		}
		a.Wait(ctx)
		if got, want := rc.Routes(), wantRoutes; !slices.Equal(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}

		// a CNAME record chain should result in a route being added if the chain
		// matches a routed domain.
		a.updateDomains([]string{"www.example.com", "example.com"})
		if err := a.ObserveDNSResponse(dnsCNAMEResponse("192.0.0.9", "www.example.com.", "chain.example.com.", "example.com.")); err != nil {
			t.Errorf("ObserveDNSResponse: %v", err)
		}
		a.Wait(ctx)
		wantRoutes = append(wantRoutes, netip.MustParsePrefix("192.0.0.9/32"))
		if got, want := rc.Routes(), wantRoutes; !slices.Equal(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}

		// a CNAME record chain should result in a route being added if the chain
		// even if only found in the middle of the chain
		if err := a.ObserveDNSResponse(dnsCNAMEResponse("192.0.0.10", "outside.example.org.", "www.example.com.", "example.org.")); err != nil {
			t.Errorf("ObserveDNSResponse: %v", err)
		}
		a.Wait(ctx)
		wantRoutes = append(wantRoutes, netip.MustParsePrefix("192.0.0.10/32"))
		if got, want := rc.Routes(), wantRoutes; !slices.Equal(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}

		wantRoutes = append(wantRoutes, netip.MustParsePrefix("2001:db8::1/128"))

		if err := a.ObserveDNSResponse(dnsResponse("example.com.", "2001:db8::1")); err != nil {
			t.Errorf("ObserveDNSResponse: %v", err)
		}
		a.Wait(ctx)
		if got, want := rc.Routes(), wantRoutes; !slices.Equal(got, want) {
			t.Errorf("got %v; want %v", got, want)
		}

		// don't re-advertise routes that have already been advertised
		if err := a.ObserveDNSResponse(dnsResponse("example.com.", "2001:db8::1")); err != nil {
			t.Errorf("ObserveDNSResponse: %v", err)
		}
		a.Wait(ctx)
		if !slices.Equal(rc.Routes(), wantRoutes) {
			t.Errorf("rc.Routes(): got %v; want %v", rc.Routes(), wantRoutes)
		}

		// don't advertise addresses that are already in a control provided route
		pfx := netip.MustParsePrefix("192.0.2.0/24")
		a.updateRoutes([]netip.Prefix{pfx})
		wantRoutes = append(wantRoutes, pfx)
		if err := a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.2.1")); err != nil {
			t.Errorf("ObserveDNSResponse: %v", err)
		}
		a.Wait(ctx)
		if !slices.Equal(rc.Routes(), wantRoutes) {
			t.Errorf("rc.Routes(): got %v; want %v", rc.Routes(), wantRoutes)
		}
		if !slices.Contains(a.domains["example.com"], netip.MustParseAddr("192.0.2.1")) {
			t.Errorf("missing %v from %v", "192.0.2.1", a.domains["exmaple.com"])
		}

		if err := eventbustest.ExpectExactly(w,
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("192.0.0.8/32")}), // from initial DNS response, via example.com
			eventbustest.Type[appctype.RouteInfo](),
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("192.0.0.9/32")}), // from CNAME response
			eventbustest.Type[appctype.RouteInfo](),
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("192.0.0.10/32")}), // from CNAME response, mid-chain
			eventbustest.Type[appctype.RouteInfo](),
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("2001:db8::1/128")}), // v6 DNS response
			eventbustest.Type[appctype.RouteInfo](),
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("192.0.2.0/24")}), // additional prefix
			eventbustest.Type[appctype.RouteInfo](),
			// N.B. no update for 192.0.2.1 as it is already covered
		); err != nil {
			t.Error(err)
		}
	}
}

func TestWildcardDomains(t *testing.T) {
	ctx := t.Context()
	bus := eventbustest.NewBus(t)
	for _, shouldStore := range []bool{false, true} {
		w := eventbustest.NewWatcher(t, bus)
		rc := &appctest.RouteCollector{}
		a := NewAppConnector(Config{
			Logf:            t.Logf,
			EventBus:        bus,
			RouteAdvertiser: rc,
			HasStoredRoutes: shouldStore,
		})
		t.Cleanup(a.Close)

		a.updateDomains([]string{"*.example.com"})
		if err := a.ObserveDNSResponse(dnsResponse("foo.example.com.", "192.0.0.8")); err != nil {
			t.Errorf("ObserveDNSResponse: %v", err)
		}
		a.Wait(ctx)
		if got, want := rc.Routes(), []netip.Prefix{netip.MustParsePrefix("192.0.0.8/32")}; !slices.Equal(got, want) {
			t.Errorf("routes: got %v; want %v", got, want)
		}
		if got, want := a.wildcards, []string{"example.com"}; !slices.Equal(got, want) {
			t.Errorf("wildcards: got %v; want %v", got, want)
		}

		a.updateDomains([]string{"*.example.com", "example.com"})
		if _, ok := a.domains["foo.example.com"]; !ok {
			t.Errorf("expected foo.example.com to be preserved in domains due to wildcard")
		}
		if got, want := a.wildcards, []string{"example.com"}; !slices.Equal(got, want) {
			t.Errorf("wildcards: got %v; want %v", got, want)
		}

		// There was an early regression where the wildcard domain was added repeatedly, this guards against that.
		a.updateDomains([]string{"*.example.com", "example.com"})
		if len(a.wildcards) != 1 {
			t.Errorf("expected only one wildcard domain, got %v", a.wildcards)
		}

		if err := eventbustest.ExpectExactly(w,
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("192.0.0.8/32")}),
			eventbustest.Type[appctype.RouteInfo](),
		); err != nil {
			t.Error(err)
		}
	}
}

// dnsResponse is a test helper that creates a DNS response buffer for the given domain and address
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

func dnsCNAMEResponse(address string, domains ...string) []byte {
	addr := netip.MustParseAddr(address)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	b.EnableCompression()
	b.StartAnswers()

	if len(domains) >= 2 {
		for i, domain := range domains[:len(domains)-1] {
			b.CNAMEResource(
				dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName(domain),
					Type:  dnsmessage.TypeCNAME,
					Class: dnsmessage.ClassINET,
					TTL:   0,
				},
				dnsmessage.CNAMEResource{
					CNAME: dnsmessage.MustNewName(domains[i+1]),
				},
			)
		}
	}

	domain := domains[len(domains)-1]

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

func prefixEqual(a, b netip.Prefix) bool {
	return a == b
}

func prefixCompare(a, b netip.Prefix) int {
	if a.Addr().Compare(b.Addr()) == 0 {
		return a.Bits() - b.Bits()
	}
	return a.Addr().Compare(b.Addr())
}

func prefixes(in ...string) []netip.Prefix {
	toRet := make([]netip.Prefix, len(in))
	for i, s := range in {
		toRet[i] = netip.MustParsePrefix(s)
	}
	return toRet
}

func TestUpdateRouteRouteRemoval(t *testing.T) {
	ctx := t.Context()
	bus := eventbustest.NewBus(t)
	for _, shouldStore := range []bool{false, true} {
		w := eventbustest.NewWatcher(t, bus)
		rc := &appctest.RouteCollector{}

		assertRoutes := func(prefix string, routes, removedRoutes []netip.Prefix) {
			if !slices.Equal(routes, rc.Routes()) {
				t.Fatalf("%s: (shouldStore=%t) routes want %v, got %v", prefix, shouldStore, routes, rc.Routes())
			}
			if !slices.Equal(removedRoutes, rc.RemovedRoutes()) {
				t.Fatalf("%s: (shouldStore=%t) removedRoutes want %v, got %v", prefix, shouldStore, removedRoutes, rc.RemovedRoutes())
			}
		}

		a := NewAppConnector(Config{
			Logf:            t.Logf,
			EventBus:        bus,
			RouteAdvertiser: rc,
			HasStoredRoutes: shouldStore,
		})
		t.Cleanup(a.Close)

		// nothing has yet been advertised
		assertRoutes("appc init", []netip.Prefix{}, []netip.Prefix{})

		a.UpdateDomainsAndRoutes([]string{}, prefixes("1.2.3.1/32", "1.2.3.2/32"))
		a.Wait(ctx)
		// the routes passed to UpdateDomainsAndRoutes have been advertised
		assertRoutes("simple update", prefixes("1.2.3.1/32", "1.2.3.2/32"), []netip.Prefix{})

		// one route the same, one different
		a.UpdateDomainsAndRoutes([]string{}, prefixes("1.2.3.1/32", "1.2.3.3/32"))
		a.Wait(ctx)
		// old behavior: routes are not removed, resulting routes are both old and new
		// (we have dupe 1.2.3.1 routes because the test RouteAdvertiser doesn't have the deduplication
		// the real one does)
		wantRoutes := prefixes("1.2.3.1/32", "1.2.3.2/32", "1.2.3.1/32", "1.2.3.3/32")
		wantRemovedRoutes := []netip.Prefix{}
		if shouldStore {
			// new behavior: routes are removed, resulting routes are new only
			wantRoutes = prefixes("1.2.3.1/32", "1.2.3.1/32", "1.2.3.3/32")
			wantRemovedRoutes = prefixes("1.2.3.2/32")
		}
		assertRoutes("removal", wantRoutes, wantRemovedRoutes)

		if err := eventbustest.Expect(w,
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("1.2.3.1/32", "1.2.3.2/32")}), // no duplicates here
			eventbustest.Type[appctype.RouteInfo](),
		); err != nil {
			t.Error(err)
		}
	}
}

func TestUpdateDomainRouteRemoval(t *testing.T) {
	ctx := t.Context()
	bus := eventbustest.NewBus(t)
	for _, shouldStore := range []bool{false, true} {
		w := eventbustest.NewWatcher(t, bus)
		rc := &appctest.RouteCollector{}

		assertRoutes := func(prefix string, routes, removedRoutes []netip.Prefix) {
			if !slices.Equal(routes, rc.Routes()) {
				t.Fatalf("%s: (shouldStore=%t) routes want %v, got %v", prefix, shouldStore, routes, rc.Routes())
			}
			if !slices.Equal(removedRoutes, rc.RemovedRoutes()) {
				t.Fatalf("%s: (shouldStore=%t) removedRoutes want %v, got %v", prefix, shouldStore, removedRoutes, rc.RemovedRoutes())
			}
		}

		a := NewAppConnector(Config{
			Logf:            t.Logf,
			EventBus:        bus,
			RouteAdvertiser: rc,
			HasStoredRoutes: shouldStore,
		})
		t.Cleanup(a.Close)

		assertRoutes("appc init", []netip.Prefix{}, []netip.Prefix{})

		a.UpdateDomainsAndRoutes([]string{"a.example.com", "b.example.com"}, []netip.Prefix{})
		a.Wait(ctx)
		// adding domains doesn't immediately cause any routes to be advertised
		assertRoutes("update domains", []netip.Prefix{}, []netip.Prefix{})

		for _, res := range [][]byte{
			dnsResponse("a.example.com.", "1.2.3.1"),
			dnsResponse("a.example.com.", "1.2.3.2"),
			dnsResponse("b.example.com.", "1.2.3.3"),
			dnsResponse("b.example.com.", "1.2.3.4"),
		} {
			if err := a.ObserveDNSResponse(res); err != nil {
				t.Errorf("ObserveDNSResponse: %v", err)
			}
		}
		a.Wait(ctx)
		// observing dns responses causes routes to be advertised
		assertRoutes("observed dns", prefixes("1.2.3.1/32", "1.2.3.2/32", "1.2.3.3/32", "1.2.3.4/32"), []netip.Prefix{})

		a.UpdateDomainsAndRoutes([]string{"a.example.com"}, []netip.Prefix{})
		a.Wait(ctx)
		// old behavior, routes are not removed
		wantRoutes := prefixes("1.2.3.1/32", "1.2.3.2/32", "1.2.3.3/32", "1.2.3.4/32")
		wantRemovedRoutes := []netip.Prefix{}
		if shouldStore {
			// new behavior, routes are removed for b.example.com
			wantRoutes = prefixes("1.2.3.1/32", "1.2.3.2/32")
			wantRemovedRoutes = prefixes("1.2.3.3/32", "1.2.3.4/32")
		}
		assertRoutes("removal", wantRoutes, wantRemovedRoutes)

		wantEvents := []any{
			// Each DNS record observed triggers an update.
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("1.2.3.1/32")}),
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("1.2.3.2/32")}),
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("1.2.3.3/32")}),
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("1.2.3.4/32")}),
		}
		if shouldStore {
			wantEvents = append(wantEvents, eqUpdate(appctype.RouteUpdate{
				Unadvertise: prefixes("1.2.3.3/32", "1.2.3.4/32"),
			}))
		}
		if err := eventbustest.Expect(w, wantEvents...); err != nil {
			t.Error(err)
		}
	}
}

func TestUpdateWildcardRouteRemoval(t *testing.T) {
	ctx := t.Context()
	bus := eventbustest.NewBus(t)
	for _, shouldStore := range []bool{false, true} {
		w := eventbustest.NewWatcher(t, bus)
		rc := &appctest.RouteCollector{}

		assertRoutes := func(prefix string, routes, removedRoutes []netip.Prefix) {
			if !slices.Equal(routes, rc.Routes()) {
				t.Fatalf("%s: (shouldStore=%t) routes want %v, got %v", prefix, shouldStore, routes, rc.Routes())
			}
			if !slices.Equal(removedRoutes, rc.RemovedRoutes()) {
				t.Fatalf("%s: (shouldStore=%t) removedRoutes want %v, got %v", prefix, shouldStore, removedRoutes, rc.RemovedRoutes())
			}
		}

		a := NewAppConnector(Config{
			Logf:            t.Logf,
			EventBus:        bus,
			RouteAdvertiser: rc,
			HasStoredRoutes: shouldStore,
		})
		t.Cleanup(a.Close)

		assertRoutes("appc init", []netip.Prefix{}, []netip.Prefix{})

		a.UpdateDomainsAndRoutes([]string{"a.example.com", "*.b.example.com"}, []netip.Prefix{})
		a.Wait(ctx)
		// adding domains doesn't immediately cause any routes to be advertised
		assertRoutes("update domains", []netip.Prefix{}, []netip.Prefix{})

		for _, res := range [][]byte{
			dnsResponse("a.example.com.", "1.2.3.1"),
			dnsResponse("a.example.com.", "1.2.3.2"),
			dnsResponse("1.b.example.com.", "1.2.3.3"),
			dnsResponse("2.b.example.com.", "1.2.3.4"),
		} {
			if err := a.ObserveDNSResponse(res); err != nil {
				t.Errorf("ObserveDNSResponse: %v", err)
			}
		}
		a.Wait(ctx)
		// observing dns responses causes routes to be advertised
		assertRoutes("observed dns", prefixes("1.2.3.1/32", "1.2.3.2/32", "1.2.3.3/32", "1.2.3.4/32"), []netip.Prefix{})

		a.UpdateDomainsAndRoutes([]string{"a.example.com"}, []netip.Prefix{})
		a.Wait(ctx)
		// old behavior, routes are not removed
		wantRoutes := prefixes("1.2.3.1/32", "1.2.3.2/32", "1.2.3.3/32", "1.2.3.4/32")
		wantRemovedRoutes := []netip.Prefix{}
		if shouldStore {
			// new behavior, routes are removed for *.b.example.com
			wantRoutes = prefixes("1.2.3.1/32", "1.2.3.2/32")
			wantRemovedRoutes = prefixes("1.2.3.3/32", "1.2.3.4/32")
		}
		assertRoutes("removal", wantRoutes, wantRemovedRoutes)

		wantEvents := []any{
			// Each DNS record observed triggers an update.
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("1.2.3.1/32")}),
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("1.2.3.2/32")}),
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("1.2.3.3/32")}),
			eqUpdate(appctype.RouteUpdate{Advertise: prefixes("1.2.3.4/32")}),
		}
		if shouldStore {
			wantEvents = append(wantEvents, eqUpdate(appctype.RouteUpdate{
				Unadvertise: prefixes("1.2.3.3/32", "1.2.3.4/32"),
			}))
		}
		if err := eventbustest.Expect(w, wantEvents...); err != nil {
			t.Error(err)
		}
	}
}

func TestRoutesWithout(t *testing.T) {
	assert := func(msg string, got, want []netip.Prefix) {
		if !slices.Equal(want, got) {
			t.Errorf("%s: want %v, got %v", msg, want, got)
		}
	}

	assert("empty routes", routesWithout([]netip.Prefix{}, []netip.Prefix{}), []netip.Prefix{})
	assert("a empty", routesWithout([]netip.Prefix{}, prefixes("1.1.1.1/32", "1.1.1.2/32")), []netip.Prefix{})
	assert("b empty", routesWithout(prefixes("1.1.1.1/32", "1.1.1.2/32"), []netip.Prefix{}), prefixes("1.1.1.1/32", "1.1.1.2/32"))
	assert("no overlap", routesWithout(prefixes("1.1.1.1/32", "1.1.1.2/32"), prefixes("1.1.1.3/32", "1.1.1.4/32")), prefixes("1.1.1.1/32", "1.1.1.2/32"))
	assert("a has fewer", routesWithout(prefixes("1.1.1.1/32", "1.1.1.2/32"), prefixes("1.1.1.1/32", "1.1.1.2/32", "1.1.1.3/32", "1.1.1.4/32")), []netip.Prefix{})
	assert("a has more", routesWithout(prefixes("1.1.1.1/32", "1.1.1.2/32", "1.1.1.3/32", "1.1.1.4/32"), prefixes("1.1.1.1/32", "1.1.1.3/32")), prefixes("1.1.1.2/32", "1.1.1.4/32"))
}

func TestRateLogger(t *testing.T) {
	clock := tstest.Clock{}
	wasCalled := false
	rl := newRateLogger(func() time.Time { return clock.Now() }, 1*time.Second, func(count int64, _ time.Time, _ int64) {
		if count != 3 {
			t.Fatalf("count for prev period: got %d, want 3", count)
		}
		wasCalled = true
	})

	for i := 0; i < 3; i++ {
		clock.Advance(1 * time.Millisecond)
		rl.update(0)
		if wasCalled {
			t.Fatalf("wasCalled: got true, want false")
		}
	}

	clock.Advance(1 * time.Second)
	rl.update(0)
	if !wasCalled {
		t.Fatalf("wasCalled: got false, want true")
	}

	wasCalled = false
	rl = newRateLogger(func() time.Time { return clock.Now() }, 1*time.Hour, func(count int64, _ time.Time, _ int64) {
		if count != 3 {
			t.Fatalf("count for prev period: got %d, want 3", count)
		}
		wasCalled = true
	})

	for i := 0; i < 3; i++ {
		clock.Advance(1 * time.Minute)
		rl.update(0)
		if wasCalled {
			t.Fatalf("wasCalled: got true, want false")
		}
	}

	clock.Advance(1 * time.Hour)
	rl.update(0)
	if !wasCalled {
		t.Fatalf("wasCalled: got false, want true")
	}
}

func TestRouteStoreMetrics(t *testing.T) {
	metricStoreRoutes(1, 1)
	metricStoreRoutes(1, 1)         // the 1 buckets value should be 2
	metricStoreRoutes(5, 5)         // the 5 buckets value should be 1
	metricStoreRoutes(6, 6)         // the 10 buckets value should be 1
	metricStoreRoutes(10001, 10001) // the over buckets value should be 1
	wanted := map[string]int64{
		"appc_store_routes_n_routes_1":    2,
		"appc_store_routes_rate_1":        2,
		"appc_store_routes_n_routes_5":    1,
		"appc_store_routes_rate_5":        1,
		"appc_store_routes_n_routes_10":   1,
		"appc_store_routes_rate_10":       1,
		"appc_store_routes_n_routes_over": 1,
		"appc_store_routes_rate_over":     1,
	}
	for _, x := range clientmetric.Metrics() {
		if x.Value() != wanted[x.Name()] {
			t.Errorf("%s: want: %d, got: %d", x.Name(), wanted[x.Name()], x.Value())
		}
	}
}

func TestMetricBucketsAreSorted(t *testing.T) {
	if !slices.IsSorted(metricStoreRoutesRateBuckets) {
		t.Errorf("metricStoreRoutesRateBuckets must be in order")
	}
	if !slices.IsSorted(metricStoreRoutesNBuckets) {
		t.Errorf("metricStoreRoutesNBuckets must be in order")
	}
}

// TestUpdateRoutesDeadlock is a regression test for a deadlock in
// LocalBackend<->AppConnector interaction. When using real LocalBackend as the
// routeAdvertiser, calls to Advertise/UnadvertiseRoutes can end up calling
// back into AppConnector via authReconfig. If everything is called
// synchronously, this results in a deadlock on AppConnector.mu.
//
// TODO(creachadair, 2025-09-18): Remove this along with the advertiser
// interface once the LocalBackend is switched to use the event bus and the
// tests have been updated not to need it.
func TestUpdateRoutesDeadlock(t *testing.T) {
	ctx := t.Context()
	bus := eventbustest.NewBus(t)
	w := eventbustest.NewWatcher(t, bus)
	rc := &appctest.RouteCollector{}
	a := NewAppConnector(Config{
		Logf:            t.Logf,
		EventBus:        bus,
		RouteAdvertiser: rc,
		HasStoredRoutes: true,
	})
	t.Cleanup(a.Close)

	advertiseCalled := new(atomic.Bool)
	unadvertiseCalled := new(atomic.Bool)
	rc.AdvertiseCallback = func() {
		// Call something that requires a.mu to be held.
		a.DomainRoutes()
		advertiseCalled.Store(true)
	}
	rc.UnadvertiseCallback = func() {
		// Call something that requires a.mu to be held.
		a.DomainRoutes()
		unadvertiseCalled.Store(true)
	}

	a.updateDomains([]string{"example.com"})
	a.Wait(ctx)

	// Trigger rc.AdveriseRoute.
	a.updateRoutes(
		[]netip.Prefix{
			netip.MustParsePrefix("127.0.0.1/32"),
			netip.MustParsePrefix("127.0.0.2/32"),
		},
	)
	a.Wait(ctx)
	// Trigger rc.UnadveriseRoute.
	a.updateRoutes(
		[]netip.Prefix{
			netip.MustParsePrefix("127.0.0.1/32"),
		},
	)
	a.Wait(ctx)

	if !advertiseCalled.Load() {
		t.Error("AdvertiseRoute was not called")
	}
	if !unadvertiseCalled.Load() {
		t.Error("UnadvertiseRoute was not called")
	}

	if want := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}; !slices.Equal(slices.Compact(rc.Routes()), want) {
		t.Fatalf("got %v, want %v", rc.Routes(), want)
	}

	if err := eventbustest.ExpectExactly(w,
		eqUpdate(appctype.RouteUpdate{Advertise: prefixes("127.0.0.1/32", "127.0.0.2/32")}),
		eventbustest.Type[appctype.RouteInfo](),
		eqUpdate(appctype.RouteUpdate{Advertise: prefixes("127.0.0.1/32"), Unadvertise: prefixes("127.0.0.2/32")}),
		eventbustest.Type[appctype.RouteInfo](),
	); err != nil {
		t.Error(err)
	}
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

// eqUpdate generates an eventbus test filter that matches a appctype.RouteUpdate
// message equal to want, or reports an error giving a human-readable diff.
func eqUpdate(want appctype.RouteUpdate) func(appctype.RouteUpdate) error {
	return func(got appctype.RouteUpdate) error {
		if diff := cmp.Diff(routeUpdateToText(got), routeUpdateToText(want),
			cmpopts.SortSlices(stdcmp.Less[string]),
		); diff != "" {
			return fmt.Errorf("wrong update (-got, +want):\n%s", diff)
		}
		return nil
	}
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"context"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	xmaps "golang.org/x/exp/maps"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/appc/appctest"
	"tailscale.com/util/mak"
	"tailscale.com/util/must"
)

func TestUpdateDomains(t *testing.T) {
	ctx := context.Background()
	a := NewAppConnector(t.Logf, nil)
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
	if got, want := xmaps.Keys(a.domains), []string{"up.example.com"}; !slices.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestUpdateRoutes(t *testing.T) {
	ctx := context.Background()
	rc := &appctest.RouteCollector{}
	a := NewAppConnector(t.Logf, rc)
	a.updateDomains([]string{"*.example.com"})

	// This route should be collapsed into the range
	a.ObserveDNSResponse(dnsResponse("a.example.com.", "192.0.2.1"))
	a.Wait(ctx)

	if !slices.Equal(rc.Routes(), []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}) {
		t.Fatalf("got %v, want %v", rc.Routes(), []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")})
	}

	// This route should not be collapsed or removed
	a.ObserveDNSResponse(dnsResponse("b.example.com.", "192.0.0.1"))
	a.Wait(ctx)

	routes := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.0.0.1/32")}
	a.updateRoutes(routes)

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
}

func TestUpdateRoutesUnadvertisesContainedRoutes(t *testing.T) {
	rc := &appctest.RouteCollector{}
	a := NewAppConnector(t.Logf, rc)
	mak.Set(&a.domains, "example.com", []netip.Addr{netip.MustParseAddr("192.0.2.1")})
	rc.SetRoutes([]netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")})
	routes := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	a.updateRoutes(routes)

	if !slices.EqualFunc(routes, rc.Routes(), prefixEqual) {
		t.Fatalf("got %v, want %v", rc.Routes(), routes)
	}
}

func TestDomainRoutes(t *testing.T) {
	rc := &appctest.RouteCollector{}
	a := NewAppConnector(t.Logf, rc)
	a.updateDomains([]string{"example.com"})
	a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8"))
	a.Wait(context.Background())

	want := map[string][]netip.Addr{
		"example.com": {netip.MustParseAddr("192.0.0.8")},
	}

	if got := a.DomainRoutes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("DomainRoutes: got %v, want %v", got, want)
	}
}

func TestObserveDNSResponse(t *testing.T) {
	ctx := context.Background()
	rc := &appctest.RouteCollector{}
	a := NewAppConnector(t.Logf, rc)

	// a has no domains configured, so it should not advertise any routes
	a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8"))
	if got, want := rc.Routes(), ([]netip.Prefix)(nil); !slices.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}

	wantRoutes := []netip.Prefix{netip.MustParsePrefix("192.0.0.8/32")}

	a.updateDomains([]string{"example.com"})
	a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8"))
	a.Wait(ctx)
	if got, want := rc.Routes(), wantRoutes; !slices.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}

	// a CNAME record chain should result in a route being added if the chain
	// matches a routed domain.
	a.updateDomains([]string{"www.example.com", "example.com"})
	a.ObserveDNSResponse(dnsCNAMEResponse("192.0.0.9", "www.example.com.", "chain.example.com.", "example.com."))
	a.Wait(ctx)
	wantRoutes = append(wantRoutes, netip.MustParsePrefix("192.0.0.9/32"))
	if got, want := rc.Routes(), wantRoutes; !slices.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}

	// a CNAME record chain should result in a route being added if the chain
	// even if only found in the middle of the chain
	a.ObserveDNSResponse(dnsCNAMEResponse("192.0.0.10", "outside.example.org.", "www.example.com.", "example.org."))
	a.Wait(ctx)
	wantRoutes = append(wantRoutes, netip.MustParsePrefix("192.0.0.10/32"))
	if got, want := rc.Routes(), wantRoutes; !slices.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}

	wantRoutes = append(wantRoutes, netip.MustParsePrefix("2001:db8::1/128"))

	a.ObserveDNSResponse(dnsResponse("example.com.", "2001:db8::1"))
	a.Wait(ctx)
	if got, want := rc.Routes(), wantRoutes; !slices.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}

	// don't re-advertise routes that have already been advertised
	a.ObserveDNSResponse(dnsResponse("example.com.", "2001:db8::1"))
	a.Wait(ctx)
	if !slices.Equal(rc.Routes(), wantRoutes) {
		t.Errorf("rc.Routes(): got %v; want %v", rc.Routes(), wantRoutes)
	}

	// don't advertise addresses that are already in a control provided route
	pfx := netip.MustParsePrefix("192.0.2.0/24")
	a.updateRoutes([]netip.Prefix{pfx})
	wantRoutes = append(wantRoutes, pfx)
	a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.2.1"))
	a.Wait(ctx)
	if !slices.Equal(rc.Routes(), wantRoutes) {
		t.Errorf("rc.Routes(): got %v; want %v", rc.Routes(), wantRoutes)
	}
	if !slices.Contains(a.domains["example.com"], netip.MustParseAddr("192.0.2.1")) {
		t.Errorf("missing %v from %v", "192.0.2.1", a.domains["exmaple.com"])
	}
}

func TestWildcardDomains(t *testing.T) {
	ctx := context.Background()
	rc := &appctest.RouteCollector{}
	a := NewAppConnector(t.Logf, rc)

	a.updateDomains([]string{"*.example.com"})
	a.ObserveDNSResponse(dnsResponse("foo.example.com.", "192.0.0.8"))
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

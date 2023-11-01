// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"net/netip"
	"slices"
	"testing"

	xmaps "golang.org/x/exp/maps"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/util/must"
)

func TestUpdateDomains(t *testing.T) {
	a := NewAppConnector(t.Logf, nil)
	a.UpdateDomains([]string{"example.com"})
	if got, want := a.Domains().AsSlice(), []string{"example.com"}; !slices.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}

	addr := netip.MustParseAddr("192.0.0.8")
	a.domains["example.com"] = append(a.domains["example.com"], addr)
	a.UpdateDomains([]string{"example.com"})

	if got, want := a.domains["example.com"], []netip.Addr{addr}; !slices.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}

	// domains are explicitly downcased on set.
	a.UpdateDomains([]string{"UP.EXAMPLE.COM"})
	if got, want := xmaps.Keys(a.domains), []string{"up.example.com"}; !slices.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestObserveDNSResponse(t *testing.T) {
	rc := &routeCollector{}
	a := NewAppConnector(t.Logf, rc)

	// a has no domains configured, so it should not advertise any routes
	a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8"))
	if got, want := rc.routes, ([]netip.Prefix)(nil); !slices.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}

	wantRoutes := []netip.Prefix{netip.MustParsePrefix("192.0.0.8/32")}

	a.UpdateDomains([]string{"example.com"})
	a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8"))
	if got, want := rc.routes, wantRoutes; !slices.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}

	wantRoutes = append(wantRoutes, netip.MustParsePrefix("2001:db8::1/128"))

	a.ObserveDNSResponse(dnsResponse("example.com.", "2001:db8::1"))
	if got, want := rc.routes, wantRoutes; !slices.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}

	// don't re-advertise routes that have already been advertised
	a.ObserveDNSResponse(dnsResponse("example.com.", "2001:db8::1"))
	if !slices.Equal(rc.routes, wantRoutes) {
		t.Errorf("got %v; want %v", rc.routes, wantRoutes)
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

// routeCollector is a test helper that collects the list of routes advertised
type routeCollector struct {
	routes []netip.Prefix
}

// routeCollector implements RouteAdvertiser
var _ RouteAdvertiser = (*routeCollector)(nil)

func (rc *routeCollector) AdvertiseRoute(pfx netip.Prefix) error {
	rc.routes = append(rc.routes, pfx)
	return nil
}

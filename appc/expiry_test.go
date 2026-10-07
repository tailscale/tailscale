// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"encoding/json"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/appc/appctest"
	"tailscale.com/tstest"
	"tailscale.com/types/appctype"
	"tailscale.com/util/eventbus/eventbustest"
)

const testRouteRetention = 10 * time.Minute

func newExpiryTestConnector(t *testing.T, clock *tstest.Clock, ri *appctype.RouteInfo) (*AppConnector, *appctest.RouteCollector) {
	t.Helper()
	rc := &appctest.RouteCollector{}
	a := NewAppConnector(Config{
		Logf: t.Logf, EventBus: eventbustest.NewBus(t), RouteAdvertiser: rc,
		HasStoredRoutes: true, RouteRetention: testRouteRetention, Clock: clock, RouteInfo: ri,
	})
	t.Cleanup(a.Close)
	return a, rc
}

func observeExpiryAnswer(t *testing.T, a *AppConnector, domain, address string, ttl uint32) {
	t.Helper()
	// Reuse the normal A/AAAA builder, changing only its resource TTLs.
	var msg dnsmessage.Message
	if err := msg.Unpack(dnsResponse(domain, address)); err != nil {
		t.Fatal(err)
	}
	for i := range msg.Answers {
		msg.Answers[i].Header.TTL = ttl
	}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ObserveDNSResponse(wire); err != nil {
		t.Fatal(err)
	}
	a.Wait(t.Context())
}

func assertExpiryRoutes(t *testing.T, rc *appctest.RouteCollector, want ...string) {
	t.Helper()
	got := slices.Clone(rc.Routes())
	slices.SortFunc(got, prefixCompare)
	got = slices.Compact(got)
	expected := prefixes(want...)
	slices.SortFunc(expected, prefixCompare)
	if !slices.Equal(got, expected) {
		t.Fatalf("routes = %v, want %v", got, expected)
	}
}

func TestRouteRetentionRotatingDNS(t *testing.T) {
	for _, address := range []string{"192.0.2.1", "2001:db8::1"} {
		t.Run(address, func(t *testing.T) {
			clock := new(tstest.Clock)
			a, rc := newExpiryTestConnector(t, clock, nil)
			a.UpdateDomains([]string{"example.com"})
			a.Wait(t.Context())
			observeExpiryAnswer(t, a, "example.com.", address, 30)
			clock.Advance(5 * time.Minute)
			a.Wait(t.Context())
			observeExpiryAnswer(t, a, "example.com.", "192.0.2.2", 30)
			clock.Advance(6 * time.Minute)
			a.Wait(t.Context())
			assertExpiryRoutes(t, rc, "192.0.2.2/32")
			clock.Advance(5 * time.Minute)
			a.Wait(t.Context())
			assertExpiryRoutes(t, rc)
			// Expiration keeps the exact configured domain discoverable.
			observeExpiryAnswer(t, a, "example.com.", address, 30)
			prefix := netip.PrefixFrom(netip.MustParseAddr(address), netip.MustParseAddr(address).BitLen())
			assertExpiryRoutes(t, rc, prefix.String())
		})
	}
}

func TestRouteRetentionRefreshAndLongTTL(t *testing.T) {
	clock := new(tstest.Clock)
	a, rc := newExpiryTestConnector(t, clock, nil)
	a.UpdateDomains([]string{"example.com"})
	a.Wait(t.Context())
	observeExpiryAnswer(t, a, "example.com.", "192.0.2.1", 1800)
	clock.Advance(5 * time.Minute)
	a.Wait(t.Context())
	// A shorter response for a second client cannot shorten the first TTL.
	observeExpiryAnswer(t, a, "example.com.", "192.0.2.1", 0)
	clock.Advance(11 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc, "192.0.2.1/32")
	clock.Advance(15 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc)
	observeExpiryAnswer(t, a, "example.com.", "192.0.2.2", 0)
	clock.Advance(5 * time.Minute)
	a.Wait(t.Context())
	observeExpiryAnswer(t, a, "example.com.", "192.0.2.2", 0)
	clock.Advance(6 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc, "192.0.2.2/32")
}

func TestRouteRetentionSharedAddress(t *testing.T) {
	clock := new(tstest.Clock)
	a, rc := newExpiryTestConnector(t, clock, nil)
	a.UpdateDomains([]string{"a.example.com", "b.example.com"})
	a.Wait(t.Context())
	observeExpiryAnswer(t, a, "a.example.com.", "192.0.2.1", 0)
	clock.Advance(5 * time.Minute)
	a.Wait(t.Context())
	observeExpiryAnswer(t, a, "b.example.com.", "192.0.2.1", 0)
	clock.Advance(6 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc, "192.0.2.1/32")
	if got := a.DomainRoutes()["a.example.com"]; len(got) != 0 {
		t.Fatalf("expired domain retains addresses: %v", got)
	}
	clock.Advance(5 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc)
}

func TestRouteRetentionPreservesControlRoutes(t *testing.T) {
	clock := new(tstest.Clock)
	a, rc := newExpiryTestConnector(t, clock, nil)
	a.UpdateDomainsAndRoutes([]string{"example.com"}, prefixes("192.0.2.1/32", "2001:db8::/64"))
	a.Wait(t.Context())
	observeExpiryAnswer(t, a, "example.com.", "192.0.2.1", 0)
	observeExpiryAnswer(t, a, "example.com.", "2001:db8::1", 0)
	clock.Advance(11 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc, "192.0.2.1/32", "2001:db8::/64")
}

func TestRouteRetentionWildcardAndCNAME(t *testing.T) {
	clock := new(tstest.Clock)
	a, rc := newExpiryTestConnector(t, clock, nil)
	a.UpdateDomains([]string{"*.example.com"})
	a.Wait(t.Context())
	var msg dnsmessage.Message
	if err := msg.Unpack(dnsCNAMEResponse("192.0.2.1", "a.example.com.", "cdn.example.net.")); err != nil {
		t.Fatal(err)
	}
	msg.Answers[0].Header.TTL = 1800
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ObserveDNSResponse(wire); err != nil {
		t.Fatal(err)
	}
	a.Wait(t.Context())
	clock.Advance(11 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc, "192.0.2.1/32")
	clock.Advance(20 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc)
	if len(a.DomainRoutes()) != 0 {
		t.Fatal("expired wildcard discovery remains in domain map")
	}
	observeExpiryAnswer(t, a, "a.example.com.", "192.0.2.2", 0)
	assertExpiryRoutes(t, rc, "192.0.2.2/32")
}

func TestRouteRetentionPersistence(t *testing.T) {
	clock := new(tstest.Clock)
	bus := eventbustest.NewBus(t)
	w := eventbustest.NewWatcher(t, bus)
	a := NewAppConnector(Config{Logf: t.Logf, EventBus: bus, Clock: clock,
		HasStoredRoutes: true, RouteRetention: testRouteRetention})
	t.Cleanup(a.Close)
	a.UpdateDomains([]string{"example.com"})
	a.Wait(t.Context())
	observeExpiryAnswer(t, a, "example.com.", "192.0.2.1", 1800)
	var saved appctype.RouteInfo
	if err := eventbustest.Expect(w, func(ri appctype.RouteInfo) bool {
		if len(ri.Domains["example.com"]) == 0 || len(ri.DomainExpiry["example.com"]) == 0 {
			return false
		}
		saved = ri
		return true
	}); err != nil {
		t.Fatal(err)
	}
	original, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(5 * time.Minute)
	a.Wait(t.Context())
	observeExpiryAnswer(t, a, "example.com.", "192.0.2.1", 1800)
	after, err := json.Marshal(saved)
	if err != nil || string(original) != string(after) {
		t.Fatal("a published snapshot changed after a later observation")
	}
	a.Close()
	var restored appctype.RouteInfo
	if err := json.Unmarshal(original, &restored); err != nil {
		t.Fatal(err)
	}
	b, rc := newExpiryTestConnector(t, clock, &restored)
	rc.SetRoutes(prefixes("192.0.2.1/32"))
	clock.Advance(26 * time.Minute)
	b.Wait(t.Context())
	// Restart does not reset the persisted deadline to another full period.
	assertExpiryRoutes(t, rc)
}

func TestRouteRetentionLegacyState(t *testing.T) {
	clock := new(tstest.Clock)
	a, rc := newExpiryTestConnector(t, clock, &appctype.RouteInfo{
		Domains: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("192.0.2.1")}},
	})
	rc.SetRoutes(prefixes("192.0.2.1/32"))
	clock.Advance(5 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc, "192.0.2.1/32")
	clock.Advance(6 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc)
}

func TestRouteRetentionDisabled(t *testing.T) {
	for _, store := range []bool{false, true} {
		for _, retention := range []time.Duration{0, testRouteRetention} {
			if store && retention > 0 {
				continue
			}
			clock := new(tstest.Clock)
			rc := &appctest.RouteCollector{}
			a := NewAppConnector(Config{Logf: t.Logf, EventBus: eventbustest.NewBus(t), Clock: clock,
				RouteAdvertiser: rc, HasStoredRoutes: store, RouteRetention: retention})
			t.Cleanup(a.Close)
			a.UpdateDomains([]string{"example.com"})
			a.Wait(t.Context())
			observeExpiryAnswer(t, a, "example.com.", "192.0.2.1", 0)
			clock.Advance(24 * time.Hour)
			a.Wait(t.Context())
			assertExpiryRoutes(t, rc, "192.0.2.1/32")
		}
	}
}

func TestRouteRetentionClose(t *testing.T) {
	clock := new(tstest.Clock)
	a, rc := newExpiryTestConnector(t, clock, nil)
	a.UpdateDomains([]string{"example.com"})
	a.Wait(t.Context())
	observeExpiryAnswer(t, a, "example.com.", "192.0.2.1", 0)
	a.Close()
	clock.Advance(time.Hour)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc, "192.0.2.1/32")
}

func TestRouteRetentionDomainRemoval(t *testing.T) {
	clock := new(tstest.Clock)
	a, rc := newExpiryTestConnector(t, clock, nil)
	a.UpdateDomains([]string{"a.example.com", "b.example.com"})
	a.Wait(t.Context())
	observeExpiryAnswer(t, a, "a.example.com.", "192.0.2.1", 0)
	observeExpiryAnswer(t, a, "b.example.com.", "192.0.2.1", 0)
	a.UpdateDomains([]string{"b.example.com"})
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc, "192.0.2.1/32")
	clock.Advance(11 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc)
}

func TestRouteRetentionBoundsDNSChurn(t *testing.T) {
	clock := new(tstest.Clock)
	a, rc := newExpiryTestConnector(t, clock, nil)
	a.UpdateDomains([]string{"*.example.com"})
	a.Wait(t.Context())
	addr := netip.MustParseAddr("192.0.2.1")
	for range 100 {
		observeExpiryAnswer(t, a, "cdn.example.com.", addr.String(), 30)
		addr = addr.Next()
		clock.Advance(time.Minute)
		a.Wait(t.Context())
		if got := len(rc.Routes()); got > 11 {
			t.Fatalf("route count grew beyond retention window: %d", got)
		}
	}
	clock.Advance(11 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc)
}

func TestRouteRetentionEventBus(t *testing.T) {
	clock := new(tstest.Clock)
	bus := eventbustest.NewBus(t)
	w := eventbustest.NewWatcher(t, bus)
	// Production uses the event bus without a RouteAdvertiser.
	a := NewAppConnector(Config{Logf: t.Logf, EventBus: bus, Clock: clock,
		HasStoredRoutes: true, RouteRetention: testRouteRetention})
	t.Cleanup(a.Close)
	a.UpdateDomains([]string{"example.com"})
	a.Wait(t.Context())
	observeExpiryAnswer(t, a, "example.com.", "192.0.2.1", 0)
	if err := eventbustest.Expect(w, eqUpdate(appctype.RouteUpdate{Advertise: prefixes("192.0.2.1/32")})); err != nil {
		t.Fatal(err)
	}
	clock.Advance(11 * time.Minute)
	a.Wait(t.Context())
	if err := eventbustest.Expect(w, eqUpdate(appctype.RouteUpdate{Unadvertise: prefixes("192.0.2.1/32")})); err != nil {
		t.Fatal(err)
	}
	if err := eventbustest.Expect(w, func(ri appctype.RouteInfo) bool {
		return len(ri.Domains["example.com"]) == 0 && len(ri.DomainExpiry) == 0
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRouteRetentionPendingAdvertisement(t *testing.T) {
	for _, clear := range []bool{false, true} {
		clock := new(tstest.Clock)
		a, rc := newExpiryTestConnector(t, clock, nil)
		a.UpdateDomains([]string{"example.com"})
		a.Wait(t.Context())
		// Pause the queue while a configuration change and a DNS observation
		// arrive. The observation must not restore the removed domain later.
		release := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		t.Cleanup(unblock)
		a.queue.Add(func() { <-release })
		if !clear {
			a.UpdateDomains(nil)
		}
		if err := a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.2.1")); err != nil {
			t.Fatal(err)
		}
		if clear {
			if err := a.ClearRoutes(); err != nil {
				t.Fatal(err)
			}
		}
		unblock()
		a.Wait(t.Context())
		assertExpiryRoutes(t, rc)
		if len(a.DomainRoutes()) != 0 {
			t.Fatal("pending advertisement restored a removed domain")
		}
	}
}

func TestRouteRetentionWithdrawalCallback(t *testing.T) {
	clock := new(tstest.Clock)
	a, rc := newExpiryTestConnector(t, clock, nil)
	rc.UnadvertiseCallback = func() { a.DomainRoutes() }
	a.UpdateDomains([]string{"example.com"})
	a.Wait(t.Context())
	observeExpiryAnswer(t, a, "example.com.", "192.0.2.1", 0)
	clock.Advance(11 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc)
}

func TestRouteRetentionPendingSharedAddress(t *testing.T) {
	clock := new(tstest.Clock)
	a, rc := newExpiryTestConnector(t, clock, nil)
	a.UpdateDomains([]string{"a.example.com", "b.example.com"})
	a.Wait(t.Context())
	observeExpiryAnswer(t, a, "a.example.com.", "192.0.2.1", 0)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	a.queue.Add(func() { <-release })
	// Queue expiration first, then observe the same address for a new domain.
	clock.Advance(11 * time.Minute)
	if err := a.ObserveDNSResponse(dnsResponse("b.example.com.", "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	unblock()
	a.Wait(t.Context())
	if len(rc.RemovedRoutes()) != 0 {
		t.Fatalf("temporarily withdrew a route with a pending observation: %v", rc.RemovedRoutes())
	}
	clock.Advance(11 * time.Minute)
	a.Wait(t.Context())
	assertExpiryRoutes(t, rc)
}

func TestRouteRetentionDisableAndReenable(t *testing.T) {
	clock := new(tstest.Clock)
	bus := eventbustest.NewBus(t)
	w := eventbustest.NewWatcher(t, bus)
	addr := netip.MustParseAddr("192.0.2.1")
	ri := &appctype.RouteInfo{
		Domains:      map[string][]netip.Addr{"example.com": {addr}},
		DomainExpiry: map[string]map[netip.Addr]time.Time{"example.com": {addr: clock.Now().Add(-time.Hour)}},
	}
	a := NewAppConnector(Config{Logf: t.Logf, EventBus: bus, Clock: clock,
		HasStoredRoutes: true, RouteInfo: ri})
	t.Cleanup(a.Close)
	var saved appctype.RouteInfo
	if err := eventbustest.Expect(w, func(ri appctype.RouteInfo) bool {
		saved = ri
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(saved.DomainExpiry) != 0 || !slices.Equal(saved.Domains["example.com"], []netip.Addr{addr}) {
		t.Fatalf("disabling expiration did not discard only deadlines: %+v", saved)
	}
	a.Close()
	b, rc := newExpiryTestConnector(t, clock, &saved)
	rc.SetRoutes(prefixes("192.0.2.1/32"))
	clock.Advance(5 * time.Minute)
	b.Wait(t.Context())
	assertExpiryRoutes(t, rc, "192.0.2.1/32")
	clock.Advance(6 * time.Minute)
	b.Wait(t.Context())
	assertExpiryRoutes(t, rc)
}

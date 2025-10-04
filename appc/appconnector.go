// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package appc implements App Connectors.
// An AppConnector provides DNS domain oriented routing of traffic. An App
// Connector becomes a DNS server for a peer, authoritative for the set of
// configured domains. DNS resolution of the target domain triggers dynamic
// publication of routes to ensure that traffic to the domain is routed through
// the App Connector.
package appc

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/execqueue"
	"tailscale.com/util/slicesx"
)

// rateLogger responds to calls to update by adding a count for the current period and
// calling the callback if any previous period has finished since update was last called
type rateLogger struct {
	interval    time.Duration
	start       time.Time
	periodStart time.Time
	periodCount int64
	now         func() time.Time
	callback    func(int64, time.Time, int64)
}

func (rl *rateLogger) currentIntervalStart(now time.Time) time.Time {
	millisSince := now.Sub(rl.start).Milliseconds() % rl.interval.Milliseconds()
	return now.Add(-(time.Duration(millisSince)) * time.Millisecond)
}

func (rl *rateLogger) update(numRoutes int64) {
	now := rl.now()
	periodEnd := rl.periodStart.Add(rl.interval)
	if periodEnd.Before(now) {
		if rl.periodCount != 0 {
			rl.callback(rl.periodCount, rl.periodStart, numRoutes)
		}
		rl.periodCount = 0
		rl.periodStart = rl.currentIntervalStart(now)
	}
	rl.periodCount++
}

func newRateLogger(now func() time.Time, interval time.Duration, callback func(int64, time.Time, int64)) *rateLogger {
	nowTime := now()
	return &rateLogger{
		callback:    callback,
		now:         now,
		interval:    interval,
		start:       nowTime,
		periodStart: nowTime,
	}
}

// RouteAdvertiser is an interface that allows the AppConnector to advertise
// newly discovered routes that need to be served through the AppConnector.
type RouteAdvertiser interface {
	// AdvertiseRoute adds one or more route advertisements skipping any that
	// are already advertised.
	AdvertiseRoute(...netip.Prefix) error

	// UnadvertiseRoute removes any matching route advertisements.
	UnadvertiseRoute(...netip.Prefix) error
}

var (
	metricStoreRoutesRateBuckets = []int64{1, 2, 3, 4, 5, 10, 100, 1000}
	metricStoreRoutesNBuckets    = []int64{1, 2, 3, 4, 5, 10, 100, 1000, 10000}
	metricStoreRoutesRate        []*clientmetric.Metric
	metricStoreRoutesN           []*clientmetric.Metric
)

func initMetricStoreRoutes() {
	for _, n := range metricStoreRoutesRateBuckets {
		metricStoreRoutesRate = append(metricStoreRoutesRate, clientmetric.NewCounter(fmt.Sprintf("appc_store_routes_rate_%d", n)))
	}
	metricStoreRoutesRate = append(metricStoreRoutesRate, clientmetric.NewCounter("appc_store_routes_rate_over"))
	for _, n := range metricStoreRoutesNBuckets {
		metricStoreRoutesN = append(metricStoreRoutesN, clientmetric.NewCounter(fmt.Sprintf("appc_store_routes_n_routes_%d", n)))
	}
	metricStoreRoutesN = append(metricStoreRoutesN, clientmetric.NewCounter("appc_store_routes_n_routes_over"))
}

func recordMetric(val int64, buckets []int64, metrics []*clientmetric.Metric) {
	if len(buckets) < 1 {
		return
	}
	// finds the first bucket where val <=, or len(buckets) if none match
	// for bucket values of 1, 10, 100; 0-1 goes to [0], 2-10 goes to [1], 11-100 goes to [2], 101+ goes to [3]
	bucket, _ := slices.BinarySearch(buckets, val)
	metrics[bucket].Add(1)
}

func metricStoreRoutes(rate, nRoutes int64) {
	if len(metricStoreRoutesRate) == 0 {
		initMetricStoreRoutes()
	}
	recordMetric(rate, metricStoreRoutesRateBuckets, metricStoreRoutesRate)
	recordMetric(nRoutes, metricStoreRoutesNBuckets, metricStoreRoutesN)
}

// AppConnector is an implementation of an AppConnector that performs
// its function as a subsystem inside of a tailscale node. At the control plane
// side App Connector routing is configured in terms of domains rather than IP
// addresses.
// The AppConnectors responsibility inside tailscaled is to apply the routing
// and domain configuration as supplied in the map response.
// DNS requests for configured domains are observed. If the domains resolve to
// routes not yet served by the AppConnector the local node configuration is
// updated to advertise the new route.
type AppConnector struct {
	// These fields are immutable after initialization.
	logf            logger.Logf
	eventBus        *eventbus.Bus
	routeAdvertiser RouteAdvertiser
	pubClient       *eventbus.Client
	updatePub       *eventbus.Publisher[appctype.RouteUpdate]
	storePub        *eventbus.Publisher[appctype.RouteInfo]

	// hasStoredRoutes records whether the connector was initialized with
	// persisted route information.
	hasStoredRoutes bool

	// mu guards the fields that follow
	mu sync.Mutex

	// domains is a map of lower case domain names with no trailing dot, to an
	// ordered list of resolved IP addresses.
	domains map[string][]netip.Addr

	// controlRoutes is the list of routes that were last supplied by control.
	controlRoutes []netip.Prefix

	// wildcards is the list of domain strings that match subdomains.
	wildcards []string

	// queue provides ordering for update operations
	queue execqueue.ExecQueue

	writeRateMinute *rateLogger
	writeRateDay    *rateLogger
}

// Config carries the settings for an [AppConnector].
type Config struct {
	// Logf is the logger to which debug logs from the connector will be sent.
	// It must be non-nil.
	Logf logger.Logf

	// EventBus receives events when the collection of routes maintained by the
	// connector is updated. It must be non-nil.
	EventBus *eventbus.Bus

	// RouteAdvertiser allows the connector to update the set of advertised routes.
	RouteAdvertiser RouteAdvertiser

	// RouteInfo, if non-nil, use used as the initial set of routes for the
	// connector.  If nil, the connector starts empty.
	RouteInfo *appctype.RouteInfo

	// HasStoredRoutes indicates that the connector should assume stored routes.
	HasStoredRoutes bool
}

// NewAppConnector creates a new AppConnector.
func NewAppConnector(c Config) *AppConnector {
	switch {
	case c.Logf == nil:
		panic("missing logger")
	case c.EventBus == nil:
		panic("missing event bus")
	}
	ec := c.EventBus.Client("appc.AppConnector")

	ac := &AppConnector{
		logf:            logger.WithPrefix(c.Logf, "appc: "),
		eventBus:        c.EventBus,
		pubClient:       ec,
		updatePub:       eventbus.Publish[appctype.RouteUpdate](ec),
		storePub:        eventbus.Publish[appctype.RouteInfo](ec),
		routeAdvertiser: c.RouteAdvertiser,
		hasStoredRoutes: c.HasStoredRoutes,
	}
	if c.RouteInfo != nil {
		ac.domains = c.RouteInfo.Domains
		ac.wildcards = c.RouteInfo.Wildcards
		ac.controlRoutes = c.RouteInfo.Control
	}
	ac.writeRateMinute = newRateLogger(time.Now, time.Minute, func(c int64, s time.Time, l int64) {
		ac.logf("routeInfo write rate: %d in minute starting at %v (%d routes)", c, s, l)
		metricStoreRoutes(c, l)
	})
	ac.writeRateDay = newRateLogger(time.Now, 24*time.Hour, func(c int64, s time.Time, l int64) {
		ac.logf("routeInfo write rate: %d in 24 hours starting at %v (%d routes)", c, s, l)
	})
	return ac
}

// ShouldStoreRoutes returns true if the appconnector was created with the controlknob on
// and is storing its discovered routes persistently.
func (e *AppConnector) ShouldStoreRoutes() bool { return e.hasStoredRoutes }

// storeRoutesLocked takes the current state of the AppConnector and persists it
func (e *AppConnector) storeRoutesLocked() {
	if e.storePub.ShouldPublish() {
		// log write rate and write size
		numRoutes := int64(len(e.controlRoutes))
		for _, rs := range e.domains {
			numRoutes += int64(len(rs))
		}
		e.writeRateMinute.update(numRoutes)
		e.writeRateDay.update(numRoutes)

		e.storePub.Publish(appctype.RouteInfo{
			// Clone here, as the subscriber will handle these outside our lock.
			Control:   slices.Clone(e.controlRoutes),
			Domains:   maps.Clone(e.domains),
			Wildcards: slices.Clone(e.wildcards),
		})
	}
}

// ClearRoutes removes all route state from the AppConnector.
func (e *AppConnector) ClearRoutes() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.controlRoutes = nil
	e.domains = nil
	e.wildcards = nil
	e.storeRoutesLocked()
	return nil
}

// UpdateDomainsAndRoutes starts an asynchronous update of the configuration
// given the new domains and routes.
func (e *AppConnector) UpdateDomainsAndRoutes(domains []string, routes []netip.Prefix) {
	e.queue.Add(func() {
		// Add the new routes first.
		e.updateRoutes(routes)
		e.updateDomains(domains)
	})
}

// UpdateDomains asynchronously replaces the current set of configured domains
// with the supplied set of domains. Domains must not contain a trailing dot,
// and should be lower case. If the domain contains a leading '*' label it
// matches all subdomains of a domain.
func (e *AppConnector) UpdateDomains(domains []string) {
	e.queue.Add(func() {
		e.updateDomains(domains)
	})
}

// Wait waits for the currently scheduled asynchronous configuration changes to
// complete.
func (e *AppConnector) Wait(ctx context.Context) {
	e.queue.Wait(ctx)
}

// Close closes the connector and cleans up resources associated with it.
// It is safe (and a noop) to call Close on nil.
func (e *AppConnector) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.queue.Shutdown() // TODO(creachadair): Should we wait for it too?
	e.pubClient.Close()
}

func (e *AppConnector) updateDomains(domains []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var oldDomains map[string][]netip.Addr
	oldDomains, e.domains = e.domains, make(map[string][]netip.Addr, len(domains))
	e.wildcards = e.wildcards[:0]
	for _, d := range domains {
		d = strings.ToLower(d)
		if len(d) == 0 {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			e.wildcards = append(e.wildcards, d[2:])
			continue
		}
		e.domains[d] = oldDomains[d]
		delete(oldDomains, d)
	}

	// Ensure that still-live wildcards addresses are preserved as well.
	for d, addrs := range oldDomains {
		for _, wc := range e.wildcards {
			if dnsname.HasSuffix(d, wc) {
				e.domains[d] = addrs
				delete(oldDomains, d)
				break
			}
		}
	}

	// Everything left in oldDomains is a domain we're no longer tracking and we
	// can unadvertise the routes.
	if e.hasStoredRoutes {
		toRemove := []netip.Prefix{}
		for _, addrs := range oldDomains {
			for _, a := range addrs {
				toRemove = append(toRemove, netip.PrefixFrom(a, a.BitLen()))
			}
		}

		if len(toRemove) != 0 {
			if ra := e.routeAdvertiser; ra != nil {
				e.queue.Add(func() {
					if err := e.routeAdvertiser.UnadvertiseRoute(toRemove...); err != nil {
						e.logf("failed to unadvertise routes on domain removal: %v: %v: %v", slicesx.MapKeys(oldDomains), toRemove, err)
					}
				})
			}
			e.updatePub.Publish(appctype.RouteUpdate{Unadvertise: toRemove})
		}
	}

	e.logf("handling domains: %v and wildcards: %v", slicesx.MapKeys(e.domains), e.wildcards)
}

// updateRoutes merges the supplied routes into the currently configured routes. The routes supplied
// by control for UpdateRoutes are supplemental to the routes discovered by DNS resolution, but are
// also more often whole ranges. UpdateRoutes will remove any single address routes that are now
// covered by new ranges.
func (e *AppConnector) updateRoutes(routes []netip.Prefix) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If there was no change since the last update, no work to do.
	if slices.Equal(e.controlRoutes, routes) {
		return
	}

	var toRemove []netip.Prefix

	// If we know e.controlRoutes is a good representation of what should be in
	// AdvertisedRoutes we can stop advertising routes that used to be in
	// e.controlRoutes but are not in routes.
	if e.hasStoredRoutes {
		toRemove = routesWithout(e.controlRoutes, routes)
	}

nextRoute:
	for _, r := range routes {
		for _, addr := range e.domains {
			for _, a := range addr {
				if r.Contains(a) && netip.PrefixFrom(a, a.BitLen()) != r {
					pfx := netip.PrefixFrom(a, a.BitLen())
					toRemove = append(toRemove, pfx)
					continue nextRoute
				}
			}
		}
	}

	if e.routeAdvertiser != nil {
		e.queue.Add(func() {
			if err := e.routeAdvertiser.AdvertiseRoute(routes...); err != nil {
				e.logf("failed to advertise routes: %v: %v", routes, err)
			}
			if err := e.routeAdvertiser.UnadvertiseRoute(toRemove...); err != nil {
				e.logf("failed to unadvertise routes: %v: %v", toRemove, err)
			}
		})
	}
	e.updatePub.Publish(appctype.RouteUpdate{
		Advertise:   routes,
		Unadvertise: toRemove,
	})

	e.controlRoutes = routes
	e.storeRoutesLocked()
}

// Domains returns the currently configured domain list.
func (e *AppConnector) Domains() views.Slice[string] {
	e.mu.Lock()
	defer e.mu.Unlock()

	return views.SliceOf(slicesx.MapKeys(e.domains))
}

// DomainRoutes returns a map of domains to resolved IP
// addresses.
func (e *AppConnector) DomainRoutes() map[string][]netip.Addr {
	e.mu.Lock()
	defer e.mu.Unlock()

	drCopy := make(map[string][]netip.Addr)
	for k, v := range e.domains {
		drCopy[k] = append(drCopy[k], v...)
	}

	return drCopy
}

// starting from the given domain that resolved to an address, find it, or any
// of the domains in the CNAME chain toward resolving it, that are routed
// domains, returning the routed domain name and a bool indicating whether a
// routed domain was found.
// e.mu must be held.
func (e *AppConnector) findRoutedDomainLocked(domain string, cnameChain map[string]string) (string, bool) {
	var isRouted bool
	for {
		_, isRouted = e.domains[domain]
		if isRouted {
			break
		}

		// match wildcard domains
		for _, wc := range e.wildcards {
			if dnsname.HasSuffix(domain, wc) {
				e.domains[domain] = nil
				isRouted = true
				break
			}
		}

		next, ok := cnameChain[domain]
		if !ok {
			break
		}
		domain = next
	}
	return domain, isRouted
}

// isAddrKnownLocked returns true if the address is known to be associated with
// the given domain. Known domain tables are updated for covered routes to speed
// up future matches.
// e.mu must be held.
func (e *AppConnector) isAddrKnownLocked(domain string, addr netip.Addr) bool {
	if e.hasDomainAddrLocked(domain, addr) {
		return true
	}
	for _, route := range e.controlRoutes {
		if route.Contains(addr) {
			// record the new address associated with the domain for faster matching in subsequent
			// requests and for diagnostic records.
			e.addDomainAddrLocked(domain, addr)
			return true
		}
	}
	return false
}

// scheduleAdvertisement schedules an advertisement of the given address
// associated with the given domain.
func (e *AppConnector) scheduleAdvertisement(domain string, routes ...netip.Prefix) {
	e.queue.Add(func() {
		if e.routeAdvertiser != nil {
			if err := e.routeAdvertiser.AdvertiseRoute(routes...); err != nil {
				e.logf("failed to advertise routes for %s: %v: %v", domain, routes, err)
				return
			}
		}
		e.updatePub.Publish(appctype.RouteUpdate{Advertise: routes})
		e.mu.Lock()
		defer e.mu.Unlock()

		for _, route := range routes {
			if !route.IsSingleIP() {
				continue
			}
			addr := route.Addr()
			if !e.hasDomainAddrLocked(domain, addr) {
				e.addDomainAddrLocked(domain, addr)
				e.logf("[v2] advertised route for %v: %v", domain, addr)
			}
		}
		e.storeRoutesLocked()
	})
}

// hasDomainAddrLocked returns true if the address has been observed in a
// resolution of domain.
func (e *AppConnector) hasDomainAddrLocked(domain string, addr netip.Addr) bool {
	_, ok := slices.BinarySearchFunc(e.domains[domain], addr, compareAddr)
	return ok
}

// addDomainAddrLocked adds the address to the list of addresses resolved for
// domain and ensures the list remains sorted. Does not attempt to deduplicate.
func (e *AppConnector) addDomainAddrLocked(domain string, addr netip.Addr) {
	e.domains[domain] = append(e.domains[domain], addr)
	slices.SortFunc(e.domains[domain], compareAddr)
}

func compareAddr(l, r netip.Addr) int {
	return l.Compare(r)
}

// routesWithout returns a without b where a and b
// are unsorted slices of netip.Prefix
func routesWithout(a, b []netip.Prefix) []netip.Prefix {
	m := make(map[netip.Prefix]bool, len(b))
	for _, p := range b {
		m[p] = true
	}
	return slicesx.Filter(make([]netip.Prefix, 0, len(a)), a, func(p netip.Prefix) bool {
		return !m[p]
	})
}

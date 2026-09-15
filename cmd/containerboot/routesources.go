// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/tailscale/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"tailscale.com/kube/routesources"
)

// Route sources: in TS_EXPERIMENTAL_ROUTE_ACCEPTOR_SOURCES mode the operator
// tells this device, through the route_sources field of its state Secret,
// which Pods on its node may be routed via the tailnet and to which of the
// routes it accepts. Enforcement uses policy routing rather than netfilter,
// because CNIs with a BPF data path (Cilium's eBPF host routing) bypass
// netfilter for Pod traffic but still perform a full route lookup that honours
// ip rules. tailscaled routes with the rule "from all lookup 52" at priority
// 5270 (5200, its base, plus 70); the rules below sit just before it, outside
// the window [5200, 5300) in which tailscaled restores its own rules when one
// is deleted:
//
//	5190  to <cluster CIDR>   lookup main         cluster-internal traffic never needs the tailnet
//	5192  from <Pod IP>       lookup <table>      an opted-in Pod: table 52 or a per-group table
//	5194  from <cluster CIDR> lookup main         every other Pod: the node's normal routes,
//	5195  from <cluster CIDR> lookup default      as if there were no route acceptor
//	5196  from <cluster CIDR> unreachable         (never fall through to table 52)
//
// A group with restricted routes gets its own routing table (from
// routesources.TableBase) holding the accepted routes that fall within the
// group's routes, via the tailscale interface; a destination outside them finds
// no route there and falls through to the bypass rules. Pods in the host
// network namespace share the node's addresses and are not subject to any of
// this.
const (
	routeSourcesPrefFastPath          = 5190
	routeSourcesPrefAllow             = 5192
	routeSourcesPrefBypassMain        = 5194
	routeSourcesPrefBypassDefault     = 5195
	routeSourcesPrefBypassUnreachable = 5196

	// tailscaleRouteTable is the routing table tailscaled installs its routes in.
	tailscaleRouteTable = 52

	routeSourcesPollInterval = 5 * time.Second
)

// routeSourcesPrefs are the rule priorities the route acceptor manages.
var routeSourcesPrefs = []int{
	routeSourcesPrefFastPath,
	routeSourcesPrefAllow,
	routeSourcesPrefBypassMain,
	routeSourcesPrefBypassDefault,
	routeSourcesPrefBypassUnreachable,
}

// ipRule is a policy routing rule the route acceptor manages: packets from src
// (if valid) to dst (if valid) are routed with table, or rejected as
// unreachable.
type ipRule struct {
	family      int // netlink.FAMILY_V4 or netlink.FAMILY_V6
	priority    int
	src, dst    netip.Prefix
	table       int
	unreachable bool
}

func (r ipRule) String() string {
	s := fmt.Sprintf("pref %d", r.priority)
	if r.src.IsValid() {
		s += " from " + r.src.String()
	}
	if r.dst.IsValid() {
		s += " to " + r.dst.String()
	}
	if r.unreachable {
		return s + " unreachable"
	}
	return fmt.Sprintf("%s lookup %d", s, r.table)
}

// ipRoute is a route in one of the route acceptor's tables, via the tailscale
// interface.
type ipRoute struct {
	family int
	table  int
	dst    netip.Prefix
}

// routeRules is the desired state derived from a routesources.Document and the
// routes the device currently accepts.
type routeRules struct {
	rules  []ipRule
	routes []ipRoute
}

func familyOf(p netip.Prefix) int {
	if p.Addr().Is4() {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

// desiredRouteRules translates doc into rules and routes, given the routes the
// device currently accepts from its peers.
func desiredRouteRules(doc *routesources.Document, accepted []netip.Prefix) (routeRules, error) {
	var out routeRules
	seenRules := map[ipRule]bool{}
	addRule := func(r ipRule) {
		if !seenRules[r] {
			seenRules[r] = true
			out.rules = append(out.rules, r)
		}
	}
	seenRoutes := map[ipRoute]bool{}
	addRoute := func(r ipRoute) {
		if !seenRoutes[r] {
			seenRoutes[r] = true
			out.routes = append(out.routes, r)
		}
	}

	for _, cidr := range doc.ClusterCIDRs {
		if !cidr.IsValid() {
			continue
		}
		cidr = cidr.Masked()
		fam := familyOf(cidr)
		addRule(ipRule{family: fam, priority: routeSourcesPrefFastPath, dst: cidr, table: unix.RT_TABLE_MAIN})
		addRule(ipRule{family: fam, priority: routeSourcesPrefBypassMain, src: cidr, table: unix.RT_TABLE_MAIN})
		addRule(ipRule{family: fam, priority: routeSourcesPrefBypassDefault, src: cidr, table: unix.RT_TABLE_DEFAULT})
		addRule(ipRule{family: fam, priority: routeSourcesPrefBypassUnreachable, src: cidr, unreachable: true})
	}

	var acceptedSet *netipx.IPSet
	{
		var b netipx.IPSetBuilder
		for _, p := range accepted {
			b.AddPrefix(p.Masked())
		}
		var err error
		if acceptedSet, err = b.IPSet(); err != nil {
			return routeRules{}, fmt.Errorf("building the set of accepted routes: %w", err)
		}
	}

	for i, g := range doc.Groups {
		table := tailscaleRouteTable
		if g.Routes != nil {
			if g.Table < routesources.TableBase || g.Table >= routesources.TableBase+routesources.TableCount {
				return routeRules{}, fmt.Errorf("group %d: routing table %d outside [%d, %d)", i, g.Table, routesources.TableBase, routesources.TableBase+routesources.TableCount)
			}
			table = g.Table
			var b netipx.IPSetBuilder
			for _, r := range g.Routes {
				b.AddPrefix(r.Masked())
			}
			b.Intersect(acceptedSet)
			set, err := b.IPSet()
			if err != nil {
				return routeRules{}, fmt.Errorf("group %d: intersecting routes: %w", i, err)
			}
			for _, p := range set.Prefixes() {
				addRoute(ipRoute{family: familyOf(p), table: table, dst: p})
			}
		}
		for _, ip := range g.IPs {
			if !ip.IsValid() {
				continue
			}
			p := netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen())
			addRule(ipRule{family: familyOf(p), priority: routeSourcesPrefAllow, src: p, table: table})
		}
	}
	return out, nil
}

// netlinker is the subset of netlink used to manage rules and routes, so that
// tests can substitute a fake.
type netlinker interface {
	RuleList(family int) ([]netlink.Rule, error)
	RuleAdd(*netlink.Rule) error
	RuleDel(*netlink.Rule) error
	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
	RouteAdd(*netlink.Route) error
	RouteDel(*netlink.Route) error
	LinkByName(name string) (netlink.Link, error)
}

type realNetlink struct{}

func (realNetlink) RuleList(family int) ([]netlink.Rule, error) { return netlink.RuleList(family) }
func (realNetlink) RuleAdd(r *netlink.Rule) error               { return netlink.RuleAdd(r) }
func (realNetlink) RuleDel(r *netlink.Rule) error               { return netlink.RuleDel(r) }
func (realNetlink) RouteListFiltered(family int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(family, filter, mask)
}
func (realNetlink) RouteAdd(r *netlink.Route) error              { return netlink.RouteAdd(r) }
func (realNetlink) RouteDel(r *netlink.Route) error              { return netlink.RouteDel(r) }
func (realNetlink) LinkByName(name string) (netlink.Link, error) { return netlink.LinkByName(name) }

// routeSources keeps the node's policy routing rules and route tables in sync
// with the document the operator writes and the routes the device accepts.
type routeSources struct {
	nl  netlinker
	tun string

	mu           sync.Mutex
	doc          *routesources.Document
	accepted     []netip.Prefix
	tables       map[int]bool // tables this device has populated, for cleanup
	loggedNoLink bool
}

func newRouteSources(nl netlinker, tun string) *routeSources {
	return &routeSources{nl: nl, tun: tun, tables: map[int]bool{}}
}

// run polls the state Secret for the document until ctx is done, applying it
// (and repairing the rules and routes) on every tick.
func (rs *routeSources) run(ctx context.Context, kc *kubeClient) {
	t := time.NewTicker(routeSourcesPollInterval)
	defer t.Stop()
	var last []byte
	for {
		b, err := kc.getRouteSources(ctx)
		switch {
		case err != nil:
			log.Printf("route sources: error reading the state Secret: %v", err)
		case len(b) == 0:
			if last == nil {
				log.Printf("route sources: waiting for the operator to write the %q field of the state Secret; no Pod is routed via the tailnet until then", kc.stateSecret)
				last = []byte{}
			}
		case !bytes.Equal(b, last):
			doc, err := routesources.Parse(b)
			if err != nil {
				log.Printf("route sources: ignoring invalid document: %v", err)
			} else {
				last = b
				rs.mu.Lock()
				rs.doc = doc
				rs.mu.Unlock()
				log.Printf("route sources: %d cluster CIDR(s), %d group(s), %d Pod address(es)", len(doc.ClusterCIDRs), len(doc.Groups), countIPs(doc))
			}
		}
		if err := rs.apply(); err != nil {
			log.Printf("route sources: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func countIPs(doc *routesources.Document) int {
	n := 0
	for _, g := range doc.Groups {
		n += len(g.IPs)
	}
	return n
}

// setAcceptedRoutes records the routes the device currently accepts and
// re-applies the document.
func (rs *routeSources) setAcceptedRoutes(routes []netip.Prefix) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.accepted = slices.Clone(routes)
	return rs.applyLocked()
}

// apply brings the node's rules and routes in line with the document.
func (rs *routeSources) apply() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.applyLocked()
}

func (rs *routeSources) applyLocked() error {
	if rs.doc == nil {
		return nil
	}
	desired, err := desiredRouteRules(rs.doc, rs.accepted)
	if err != nil {
		return err
	}
	return rs.reconcileLocked(desired)
}

// cleanup removes every rule and route the device manages.
func (rs *routeSources) cleanup() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.reconcileLocked(routeRules{})
}

// reconcileLocked adds what is missing from desired and removes what is
// extra, in an order that never points a rule at a table that does not yet
// hold its routes: routes are added first and deleted last.
func (rs *routeSources) reconcileLocked(desired routeRules) error {
	var errs []error

	linkIndex := 0
	if len(desired.routes) > 0 {
		if link, err := rs.nl.LinkByName(rs.tun); err != nil {
			if !rs.loggedNoLink {
				log.Printf("route sources: interface %s not found yet, routes of restricted groups will be installed once it exists", rs.tun)
				rs.loggedNoLink = true
			}
		} else {
			linkIndex = link.Attrs().Index
			rs.loggedNoLink = false
		}
	}

	// Routes, per table.
	tables := map[int]bool{}
	for t := range rs.tables {
		tables[t] = true
	}
	wantRoutes := map[ipRoute]bool{}
	for _, r := range desired.routes {
		wantRoutes[r] = true
		tables[r.table] = true
	}
	haveRoutes := map[ipRoute]netlink.Route{}
	for t := range tables {
		for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			routes, err := rs.nl.RouteListFiltered(fam, &netlink.Route{Table: t}, netlink.RT_FILTER_TABLE)
			if err != nil {
				errs = append(errs, fmt.Errorf("listing routes in table %d: %w", t, err))
				continue
			}
			for _, nr := range routes {
				if nr.Dst == nil {
					continue
				}
				dst, ok := netipx.FromStdIPNet(nr.Dst)
				if !ok {
					continue
				}
				haveRoutes[ipRoute{family: fam, table: t, dst: dst.Masked()}] = nr
			}
		}
	}
	populated := map[int]bool{}
	for _, r := range desired.routes {
		if _, ok := haveRoutes[r]; ok {
			populated[r.table] = true
			continue
		}
		if linkIndex == 0 {
			continue
		}
		if err := rs.nl.RouteAdd(&netlink.Route{LinkIndex: linkIndex, Dst: netipx.PrefixIPNet(r.dst), Table: r.table}); err != nil && !errors.Is(err, unix.EEXIST) {
			errs = append(errs, fmt.Errorf("adding route %s to table %d: %w", r.dst, r.table, err))
			continue
		}
		populated[r.table] = true
	}

	// Rules.
	wantRules := map[ipRule]bool{}
	for _, r := range desired.rules {
		wantRules[r] = true
	}
	haveRules := map[ipRule]bool{}
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := rs.nl.RuleList(fam)
		if err != nil {
			if fam == netlink.FAMILY_V6 && (errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.ENOENT)) {
				continue
			}
			errs = append(errs, fmt.Errorf("listing rules: %w", err))
			continue
		}
		for _, nr := range rules {
			if !slices.Contains(routeSourcesPrefs, nr.Priority) {
				continue
			}
			haveRules[ipRuleFromNetlink(fam, nr)] = true
		}
	}
	for _, r := range desired.rules {
		if haveRules[r] {
			continue
		}
		if err := rs.nl.RuleAdd(r.netlinkRule()); err != nil && !errors.Is(err, unix.EEXIST) {
			if r.family == netlink.FAMILY_V6 && errors.Is(err, unix.EAFNOSUPPORT) {
				continue
			}
			errs = append(errs, fmt.Errorf("adding rule %v: %w", r, err))
		}
	}
	for r := range haveRules {
		if wantRules[r] {
			continue
		}
		if err := rs.nl.RuleDel(r.netlinkRule()); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("deleting rule %v: %w", r, err))
		}
	}

	// Stale routes.
	for r, nr := range haveRoutes {
		if wantRoutes[r] {
			continue
		}
		if err := rs.nl.RouteDel(&nr); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, fmt.Errorf("deleting route %s from table %d: %w", r.dst, r.table, err))
			populated[r.table] = true
		}
	}
	rs.tables = populated
	return errors.Join(errs...)
}

// netlinkRule converts r to a netlink rule for adding or deleting it.
func (r ipRule) netlinkRule() *netlink.Rule {
	nr := netlink.NewRule()
	nr.Family = r.family
	nr.Priority = r.priority
	if r.src.IsValid() {
		nr.Src = netipx.PrefixIPNet(r.src)
	}
	if r.dst.IsValid() {
		nr.Dst = netipx.PrefixIPNet(r.dst)
	}
	if r.unreachable {
		nr.Type = unix.RTN_UNREACHABLE
	} else {
		nr.Table = r.table
	}
	return nr
}

// ipRuleFromNetlink converts a listed rule of the given family to an ipRule,
// normalizing what the kernel reports so that it compares equal to what was
// added.
func ipRuleFromNetlink(family int, nr netlink.Rule) ipRule {
	r := ipRule{family: family, priority: nr.Priority}
	if nr.Src != nil {
		if p, ok := netipx.FromStdIPNet(nr.Src); ok {
			r.src = p.Masked()
		}
	}
	if nr.Dst != nil {
		if p, ok := netipx.FromStdIPNet(nr.Dst); ok {
			r.dst = p.Masked()
		}
	}
	if nr.Type == unix.RTN_UNREACHABLE {
		r.unreachable = true
	} else {
		r.table = nr.Table
	}
	return r
}

// sortedRules returns rules in a stable order, for logs and tests.
func sortedRules(rules []ipRule) []ipRule {
	out := slices.Clone(rules)
	slices.SortFunc(out, func(a, b ipRule) int {
		return cmp.Or(
			cmp.Compare(a.priority, b.priority),
			cmp.Compare(a.family, b.family),
			cmp.Compare(a.String(), b.String()),
		)
	})
	return out
}

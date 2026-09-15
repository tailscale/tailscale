// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/kube/routesources"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestDesiredRouteRules(t *testing.T) {
	doc := &routesources.Document{
		Version:      routesources.Version,
		ClusterCIDRs: []netip.Prefix{pfx("10.244.0.0/16"), pfx("fd00:10:244::/56")},
		Groups: []routesources.Group{
			{IPs: []netip.Addr{netip.MustParseAddr("10.244.1.5")}},
			{Routes: []netip.Prefix{pfx("10.20.0.0/16"), pfx("10.30.0.0/16")}, Table: 5301, IPs: []netip.Addr{netip.MustParseAddr("10.244.1.9"), netip.MustParseAddr("fd00:10:244::9")}},
		},
	}
	accepted := []netip.Prefix{pfx("10.20.5.0/24"), pfx("10.40.0.0/16"), pfx("fd00:20::/64")}
	got, err := desiredRouteRules(doc, accepted)
	if err != nil {
		t.Fatal(err)
	}
	main, def := unix.RT_TABLE_MAIN, unix.RT_TABLE_DEFAULT
	wantRules := []ipRule{
		{family: netlink.FAMILY_V4, priority: routeSourcesPrefFastPath, dst: pfx("10.244.0.0/16"), table: main},
		{family: netlink.FAMILY_V6, priority: routeSourcesPrefFastPath, dst: pfx("fd00:10:244::/56"), table: main},
		{family: netlink.FAMILY_V4, priority: routeSourcesPrefAllow, src: pfx("10.244.1.5/32"), table: tailscaleRouteTable},
		{family: netlink.FAMILY_V4, priority: routeSourcesPrefAllow, src: pfx("10.244.1.9/32"), table: 5301},
		{family: netlink.FAMILY_V6, priority: routeSourcesPrefAllow, src: pfx("fd00:10:244::9/128"), table: 5301},
		{family: netlink.FAMILY_V4, priority: routeSourcesPrefBypassMain, src: pfx("10.244.0.0/16"), table: main},
		{family: netlink.FAMILY_V6, priority: routeSourcesPrefBypassMain, src: pfx("fd00:10:244::/56"), table: main},
		{family: netlink.FAMILY_V4, priority: routeSourcesPrefBypassDefault, src: pfx("10.244.0.0/16"), table: def},
		{family: netlink.FAMILY_V6, priority: routeSourcesPrefBypassDefault, src: pfx("fd00:10:244::/56"), table: def},
		{family: netlink.FAMILY_V4, priority: routeSourcesPrefBypassUnreachable, src: pfx("10.244.0.0/16"), unreachable: true},
		{family: netlink.FAMILY_V6, priority: routeSourcesPrefBypassUnreachable, src: pfx("fd00:10:244::/56"), unreachable: true},
	}
	if diff := diffRuleSets(sortedRules(got.rules), sortedRules(wantRules)); diff != "" {
		t.Errorf("rules differ:\n%s", diff)
	}
	// Only the accepted routes that fall within the group's routes are installed.
	wantRoutes := []ipRoute{{family: netlink.FAMILY_V4, table: 5301, dst: pfx("10.20.5.0/24")}}
	if !slices.Equal(got.routes, wantRoutes) {
		t.Errorf("routes = %v, want %v", got.routes, wantRoutes)
	}

	// A restricted group with a table outside the reserved range is rejected.
	bad := &routesources.Document{Version: routesources.Version, Groups: []routesources.Group{{Routes: []netip.Prefix{pfx("10.20.0.0/16")}, Table: tailscaleRouteTable}}}
	if _, err := desiredRouteRules(bad, nil); err == nil {
		t.Error("group with table 52 accepted")
	}
}

func diffRuleSets(got, want []ipRule) string {
	var out string
	for _, r := range got {
		if !slices.Contains(want, r) {
			out += fmt.Sprintf("unexpected: %v (family %d)\n", r, r.family)
		}
	}
	for _, r := range want {
		if !slices.Contains(got, r) {
			out += fmt.Sprintf("missing:    %v (family %d)\n", r, r.family)
		}
	}
	return out
}

// fakeNetlink is an in-memory netlinker.
type fakeNetlink struct {
	linkIndex int // 0: the interface does not exist
	rules     []netlink.Rule
	routes    []netlink.Route
	ops       int
}

func (f *fakeNetlink) RuleList(family int) ([]netlink.Rule, error) {
	var out []netlink.Rule
	for _, r := range f.rules {
		if r.Family == family {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeNetlink) RuleAdd(r *netlink.Rule) error {
	f.ops++
	for _, have := range f.rules {
		if ipRuleFromNetlink(have.Family, have) == ipRuleFromNetlink(r.Family, *r) {
			return unix.EEXIST
		}
	}
	f.rules = append(f.rules, *r)
	return nil
}

func (f *fakeNetlink) RuleDel(r *netlink.Rule) error {
	f.ops++
	want := ipRuleFromNetlink(r.Family, *r)
	for i, have := range f.rules {
		if ipRuleFromNetlink(have.Family, have) == want {
			f.rules = slices.Delete(f.rules, i, i+1)
			return nil
		}
	}
	return unix.ENOENT
}

func (f *fakeNetlink) RouteListFiltered(family int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	var out []netlink.Route
	for _, r := range f.routes {
		if r.Family != family {
			continue
		}
		if mask&netlink.RT_FILTER_TABLE != 0 && r.Table != filter.Table {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func routeKey(r *netlink.Route) string {
	return fmt.Sprintf("%d/%d/%s", r.Family, r.Table, r.Dst)
}

func (f *fakeNetlink) RouteAdd(r *netlink.Route) error {
	f.ops++
	if f.linkIndex == 0 || r.LinkIndex != f.linkIndex {
		return unix.ENODEV
	}
	if r.Family == 0 {
		r.Family = netlink.FAMILY_V6
		if r.Dst.IP.To4() != nil {
			r.Family = netlink.FAMILY_V4
		}
	}
	for _, have := range f.routes {
		if routeKey(&have) == routeKey(r) {
			return unix.EEXIST
		}
	}
	f.routes = append(f.routes, *r)
	return nil
}

func (f *fakeNetlink) RouteDel(r *netlink.Route) error {
	f.ops++
	for i, have := range f.routes {
		if routeKey(&have) == routeKey(r) {
			f.routes = slices.Delete(f.routes, i, i+1)
			return nil
		}
	}
	return unix.ESRCH
}

func (f *fakeNetlink) LinkByName(name string) (netlink.Link, error) {
	if f.linkIndex == 0 {
		return nil, errors.New("link not found")
	}
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: f.linkIndex}}, nil
}

func (f *fakeNetlink) ruleStrings() []string {
	var out []string
	for _, r := range f.rules {
		out = append(out, ipRuleFromNetlink(r.Family, r).String())
	}
	slices.Sort(out)
	return out
}

func (f *fakeNetlink) routeStrings() []string {
	var out []string
	for _, r := range f.routes {
		out = append(out, fmt.Sprintf("%s table %d", r.Dst, r.Table))
	}
	slices.Sort(out)
	return out
}

func TestRouteSourcesReconcile(t *testing.T) {
	nl := &fakeNetlink{linkIndex: 7}
	rs := newRouteSources(nl, "tailscale0")
	doc := &routesources.Document{
		Version:      routesources.Version,
		ClusterCIDRs: []netip.Prefix{pfx("10.244.0.0/16")},
		Groups: []routesources.Group{
			{IPs: []netip.Addr{netip.MustParseAddr("10.244.1.5")}},
			{Routes: []netip.Prefix{pfx("10.20.0.0/16")}, Table: 5301, IPs: []netip.Addr{netip.MustParseAddr("10.244.1.9")}},
		},
	}
	rs.doc = doc
	if err := rs.setAcceptedRoutes([]netip.Prefix{pfx("10.20.0.0/16"), pfx("10.99.0.0/24")}); err != nil {
		t.Fatal(err)
	}
	wantRules := []string{
		"pref 5190 to 10.244.0.0/16 lookup 254",
		"pref 5192 from 10.244.1.5/32 lookup 52",
		"pref 5192 from 10.244.1.9/32 lookup 5301",
		"pref 5194 from 10.244.0.0/16 lookup 254",
		"pref 5195 from 10.244.0.0/16 lookup 253",
		"pref 5196 from 10.244.0.0/16 unreachable",
	}
	if got := nl.ruleStrings(); !slices.Equal(got, wantRules) {
		t.Errorf("rules after apply = %v, want %v", got, wantRules)
	}
	if got, want := nl.routeStrings(), []string{"10.20.0.0/16 table 5301"}; !slices.Equal(got, want) {
		t.Errorf("routes after apply = %v, want %v", got, want)
	}

	// Applying again changes nothing.
	ops := nl.ops
	if err := rs.apply(); err != nil {
		t.Fatal(err)
	}
	if nl.ops != ops {
		t.Errorf("second apply performed %d netlink operations", nl.ops-ops)
	}

	// A Pod leaves the restricted group and the accepted routes change.
	rs.mu.Lock()
	rs.doc.Groups[1].IPs = nil
	rs.mu.Unlock()
	if err := rs.setAcceptedRoutes([]netip.Prefix{pfx("10.20.1.0/24")}); err != nil {
		t.Fatal(err)
	}
	wantRules = []string{
		"pref 5190 to 10.244.0.0/16 lookup 254",
		"pref 5192 from 10.244.1.5/32 lookup 52",
		"pref 5194 from 10.244.0.0/16 lookup 254",
		"pref 5195 from 10.244.0.0/16 lookup 253",
		"pref 5196 from 10.244.0.0/16 unreachable",
	}
	if got := nl.ruleStrings(); !slices.Equal(got, wantRules) {
		t.Errorf("rules after update = %v, want %v", got, wantRules)
	}
	if got, want := nl.routeStrings(), []string{"10.20.1.0/24 table 5301"}; !slices.Equal(got, want) {
		t.Errorf("routes after update = %v, want %v", got, want)
	}

	// Cleanup removes everything, including routes of a table no group uses any more.
	rs.mu.Lock()
	rs.doc.Groups = rs.doc.Groups[:1]
	rs.mu.Unlock()
	if err := rs.cleanup(); err != nil {
		t.Fatal(err)
	}
	if got := nl.ruleStrings(); len(got) != 0 {
		t.Errorf("rules after cleanup = %v, want none", got)
	}
	if got := nl.routeStrings(); len(got) != 0 {
		t.Errorf("routes after cleanup = %v, want none", got)
	}
}

func TestRouteSourcesReconcileWithoutInterface(t *testing.T) {
	nl := &fakeNetlink{}
	rs := newRouteSources(nl, "tailscale0")
	rs.doc = &routesources.Document{
		Version:      routesources.Version,
		ClusterCIDRs: []netip.Prefix{pfx("10.244.0.0/16")},
		Groups:       []routesources.Group{{Routes: []netip.Prefix{pfx("10.20.0.0/16")}, Table: 5301, IPs: []netip.Addr{netip.MustParseAddr("10.244.1.9")}}},
	}
	// Rules go in even before tailscaled has created the interface, so that nothing is routed via the tailnet
	// by mistake; the routes follow once it exists.
	if err := rs.setAcceptedRoutes([]netip.Prefix{pfx("10.20.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if got := nl.ruleStrings(); !slices.Contains(got, "pref 5192 from 10.244.1.9/32 lookup 5301") {
		t.Errorf("rules without interface = %v", got)
	}
	if got := nl.routeStrings(); len(got) != 0 {
		t.Errorf("routes without interface = %v, want none", got)
	}
	nl.linkIndex = 3
	if err := rs.apply(); err != nil {
		t.Fatal(err)
	}
	if got, want := nl.routeStrings(), []string{"10.20.0.0/16 table 5301"}; !slices.Equal(got, want) {
		t.Errorf("routes once the interface exists = %v, want %v", got, want)
	}
}

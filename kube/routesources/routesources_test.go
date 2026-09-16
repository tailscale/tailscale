// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routesources

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	doc, err := Parse([]byte(`{"version":1,"clusterCIDRs":["10.244.0.0/16"],"groups":[{"routes":null,"ips":["10.244.1.5"]},{"routes":["10.20.0.0/16"],"table":5301,"ips":["10.244.1.9"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Groups[0].Routes != nil {
		t.Errorf("group 0 routes = %v, want nil (all routes)", doc.Groups[0].Routes)
	}
	if got := doc.Groups[1].Table; got != 5301 {
		t.Errorf("group 1 table = %d, want 5301", got)
	}
	for _, bad := range []string{
		`{"version":2}`,
		`{"version":1,"groups":[{"routes":["10.20.0.0/16"],"table":52,"ips":[]}]}`,
		`{"version":1,"groups":[{"routes":["10.20.0.0/16"],"ips":[]}]}`,
		`nope`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%s) succeeded, want error", bad)
		}
	}
}

func TestMarshalNormalizes(t *testing.T) {
	a := &Document{
		Version:      Version,
		ClusterCIDRs: []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12"), netip.MustParsePrefix("10.244.0.0/16")},
		Groups: []Group{
			{Routes: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16"), netip.MustParsePrefix("10.20.0.0/16")}, Table: 5301, IPs: []netip.Addr{netip.MustParseAddr("10.244.1.9"), netip.MustParseAddr("10.244.1.2"), netip.MustParseAddr("10.244.1.9")}},
			{IPs: []netip.Addr{netip.MustParseAddr("10.244.1.5")}},
		},
	}
	b := &Document{
		Version:      Version,
		ClusterCIDRs: []netip.Prefix{netip.MustParsePrefix("10.244.0.0/16"), netip.MustParsePrefix("10.96.0.0/12")},
		Groups: []Group{
			{IPs: []netip.Addr{netip.MustParseAddr("10.244.1.5")}},
			{Routes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.30.0.0/16")}, Table: 5301, IPs: []netip.Addr{netip.MustParseAddr("10.244.1.2"), netip.MustParseAddr("10.244.1.9")}},
		},
	}
	ab, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	bb, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(ab) != string(bb) {
		t.Errorf("documents encode differently:\n%s\n%s", ab, bb)
	}
	if !strings.Contains(string(ab), `"routes":null`) {
		t.Errorf("all-routes group does not encode routes as null: %s", ab)
	}
}

func TestTableFor(t *testing.T) {
	routes := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	t1, err := TableFor(routes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if t1 < TableBase || t1 >= TableBase+TableCount {
		t.Fatalf("table %d out of range", t1)
	}
	// Order does not matter, and the result is stable.
	t2, _ := TableFor([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, map[int]bool{})
	if t1 != t2 {
		t.Errorf("TableFor is not stable: %d vs %d", t1, t2)
	}
	// A taken table is probed past.
	t3, _ := TableFor(routes, map[int]bool{t1: true})
	if t3 == t1 {
		t.Errorf("TableFor returned a taken table")
	}
	if _, err := TableFor(routes, map[int]bool{}); err != nil {
		t.Fatal(err)
	}
	taken := make(map[int]bool, TableCount)
	for i := range TableCount {
		taken[TableBase+i] = true
	}
	if _, err := TableFor(routes, taken); err == nil {
		t.Error("TableFor with every table taken succeeded")
	}
}

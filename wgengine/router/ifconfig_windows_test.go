// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func randIP() netip.Addr {
	b := byte(rand.Intn(3))
	return netip.AddrFrom4([4]byte{b, b, b, b})
}

func randRouteData() *winipcfg.RouteData {
	return &winipcfg.RouteData{
		Destination: netip.PrefixFrom(randIP(), rand.Intn(30)+1),
		NextHop:     randIP(),
		Metric:      uint32(rand.Intn(3)),
	}
}

func TestRouteLess(t *testing.T) {
	type D = winipcfg.RouteData
	ipnet := netip.MustParsePrefix
	tests := []struct {
		ri, rj *winipcfg.RouteData
		want   bool
	}{
		{
			ri:   &D{Metric: 1},
			rj:   &D{Metric: 2},
			want: true,
		},
		{
			ri:   &D{Destination: ipnet("1.1.0.0/16"), Metric: 2},
			rj:   &D{Destination: ipnet("2.2.0.0/16"), Metric: 1},
			want: true,
		},
		{
			ri:   &D{Destination: ipnet("1.1.0.0/16"), Metric: 1},
			rj:   &D{Destination: ipnet("2.2.0.0/16"), Metric: 1},
			want: true,
		},
		{
			ri:   &D{Destination: ipnet("1.1.0.0/32"), Metric: 2},
			rj:   &D{Destination: ipnet("1.1.0.0/16"), Metric: 1},
			want: true,
		},
		{
			ri:   &D{Destination: ipnet("1.1.0.0/32"), Metric: 1},
			rj:   &D{Destination: ipnet("1.1.0.0/16"), Metric: 1},
			want: true,
		},
		{
			ri:   &D{Destination: ipnet("1.1.0.0/16"), Metric: 1, NextHop: netip.MustParseAddr("3.3.3.3")},
			rj:   &D{Destination: ipnet("1.1.0.0/16"), Metric: 1, NextHop: netip.MustParseAddr("4.4.4.4")},
			want: true,
		},
	}
	for i, tt := range tests {
		got := routeDataLess(tt.ri, tt.rj)
		if got != tt.want {
			t.Errorf("%v. less = %v; want %v", i, got, tt.want)
		}
		back := routeDataLess(tt.rj, tt.ri)
		if back && got {
			t.Errorf("%v. less both ways", i)
		}
	}
}

func TestRouteDataLessConsistent(t *testing.T) {
	for i := 0; i < 10000; i++ {
		ri := randRouteData()
		rj := randRouteData()
		if routeDataLess(ri, rj) && routeDataLess(rj, ri) {
			t.Fatalf("both compare less to each other:\n\t%#v\nand\n\t%#v", ri, rj)
		}
	}
}

func nets(cidrs ...string) (ret []netip.Prefix) {
	for _, s := range cidrs {
		ret = append(ret, netip.MustParsePrefix(s))
	}
	return
}

func nilIfEmpty[E any](s []E) []E {
	if len(s) == 0 {
		return nil
	}
	return s
}

func TestDeltaNets(t *testing.T) {
	tests := []struct {
		a, b             []netip.Prefix
		wantAdd, wantDel []netip.Prefix
	}{
		{
			a:       nets("1.2.3.4/24", "1.2.3.4/31", "1.2.3.3/32", "10.0.1.1/32", "100.0.1.1/32"),
			b:       nets("10.0.1.1/32", "100.0.2.1/32", "1.2.3.3/32", "1.2.3.4/24"),
			wantAdd: nets("100.0.2.1/32"),
			wantDel: nets("1.2.3.4/31", "100.0.1.1/32"),
		},
		{
			a:       nets("fe80::99d0:ec2d:b2e7:536b/64", "100.84.36.11/32"),
			b:       nets("100.84.36.11/32"),
			wantDel: nets("fe80::99d0:ec2d:b2e7:536b/64"),
		},
		{
			a:       nets("100.84.36.11/32", "fe80::99d0:ec2d:b2e7:536b/64"),
			b:       nets("100.84.36.11/32"),
			wantDel: nets("fe80::99d0:ec2d:b2e7:536b/64"),
		},
		{
			a:       nets("100.84.36.11/32", "fe80::99d0:ec2d:b2e7:536b/64"),
			b:       nets("100.84.36.11/32"),
			wantDel: nets("fe80::99d0:ec2d:b2e7:536b/64"),
		},
	}
	for i, tt := range tests {
		add, del := deltaNets(tt.a, tt.b)
		if !reflect.DeepEqual(nilIfEmpty(add), nilIfEmpty(tt.wantAdd)) {
			t.Errorf("[%d] add:\n  got: %v\n want: %v\n", i, add, tt.wantAdd)
		}
		if !reflect.DeepEqual(nilIfEmpty(del), nilIfEmpty(tt.wantDel)) {
			t.Errorf("[%d] del:\n  got: %v\n want: %v\n", i, del, tt.wantDel)
		}
	}
}

func formatRouteData(rds []*winipcfg.RouteData) string {
	var b strings.Builder
	for _, rd := range rds {
		b.WriteString(fmt.Sprintf("%+v", rd))
	}
	return b.String()
}

func equalRouteDatas(a, b []*winipcfg.RouteData) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if routeDataCompare(a[i], b[i]) != 0 {
			return false
		}
	}
	return true
}

func ipnet4(ip string, bits int) netip.Prefix {
	return netip.PrefixFrom(netip.MustParseAddr(ip), bits)
}

func TestFilterRoutes(t *testing.T) {
	var h0 netip.Addr

	in := []*winipcfg.RouteData{
		// LinkLocal and Loopback routes.
		{ipnet4("169.254.0.0", 16), h0, 1},
		{ipnet4("169.254.255.255", 32), h0, 1},
		{ipnet4("127.0.0.0", 8), h0, 1},
		{ipnet4("127.255.255.255", 32), h0, 1},
		// Local LAN routes.
		{ipnet4("192.168.0.0", 24), h0, 1},
		{ipnet4("192.168.0.255", 32), h0, 1},
		{ipnet4("192.168.1.0", 25), h0, 1},
		{ipnet4("192.168.1.127", 32), h0, 1},
		// Some random other route.
		{ipnet4("192.168.2.23", 32), h0, 1},
		// Our own tailscale address.
		{ipnet4("100.100.100.100", 32), h0, 1},
		// Other tailscale addresses.
		{ipnet4("100.100.100.101", 32), h0, 1},
		{ipnet4("100.100.100.102", 32), h0, 1},
	}
	want := []*winipcfg.RouteData{
		{ipnet4("169.254.0.0", 16), h0, 1},
		{ipnet4("127.0.0.0", 8), h0, 1},
		{ipnet4("192.168.0.0", 24), h0, 1},
		{ipnet4("192.168.1.0", 25), h0, 1},
		{ipnet4("192.168.2.23", 32), h0, 1},
		{ipnet4("100.100.100.101", 32), h0, 1},
		{ipnet4("100.100.100.102", 32), h0, 1},
	}

	got := filterRoutes(in, mustCIDRs("100.100.100.100/32"))
	if !equalRouteDatas(got, want) {
		t.Errorf("\ngot:  %v\n  want: %v\n", formatRouteData(got), formatRouteData(want))
	}
}

func TestDeltaRouteData(t *testing.T) {
	var h0 netip.Addr
	h1 := netip.MustParseAddr("99.99.99.99")
	h2 := netip.MustParseAddr("99.99.9.99")

	a := []*winipcfg.RouteData{
		{ipnet4("1.2.3.4", 32), h0, 1},
		{ipnet4("1.2.3.4", 24), h1, 2},
		{ipnet4("1.2.3.4", 24), h2, 1},
		{ipnet4("1.2.3.5", 32), h0, 1},
	}
	b := []*winipcfg.RouteData{
		{ipnet4("1.2.3.5", 32), h0, 1},
		{ipnet4("1.2.3.4", 24), h1, 2},
		{ipnet4("1.2.3.4", 24), h2, 2},
	}
	add, del := deltaRouteData(a, b)

	wantAdd := []*winipcfg.RouteData{
		{ipnet4("1.2.3.4", 24), h2, 2},
	}
	wantDel := []*winipcfg.RouteData{
		{ipnet4("1.2.3.4", 32), h0, 1},
		{ipnet4("1.2.3.4", 24), h2, 1},
	}

	if !equalRouteDatas(add, wantAdd) {
		t.Errorf("add:\n   got: %v\n  want: %v\n", formatRouteData(add), formatRouteData(wantAdd))
	}
	if !equalRouteDatas(del, wantDel) {
		t.Errorf("del:\n   got: %v\n  want: %v\n", formatRouteData(del), formatRouteData(wantDel))
	}
}

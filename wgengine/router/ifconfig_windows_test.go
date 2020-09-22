// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"testing"

	winipcfg "github.com/tailscale/winipcfg-go"
	"inet.af/netaddr"
)

func randIP() net.IP {
	b := byte(rand.Intn(3))
	return net.IP{b, b, b, b}
}

func randRouteData() *winipcfg.RouteData {
	return &winipcfg.RouteData{
		Destination: net.IPNet{
			IP:   randIP(),
			Mask: net.CIDRMask(rand.Intn(3)+1, 32),
		},
		NextHop: randIP(),
		Metric:  uint32(rand.Intn(3)),
	}
}

func TestRouteLess(t *testing.T) {
	type D = winipcfg.RouteData
	ipnet := func(s string) net.IPNet {
		ipp, err := netaddr.ParseIPPrefix(s)
		if err != nil {
			t.Fatalf("error parsing test data %q: %v", s, err)
		}
		return *ipp.IPNet()
	}

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
			ri:   &D{Destination: ipnet("1.1.0.0/16"), Metric: 1, NextHop: net.ParseIP("3.3.3.3")},
			rj:   &D{Destination: ipnet("1.1.0.0/16"), Metric: 1, NextHop: net.ParseIP("4.4.4.4")},
			want: true,
		},
	}
	for i, tt := range tests {
		got := routeLess(tt.ri, tt.rj)
		if got != tt.want {
			t.Errorf("%v. less = %v; want %v", i, got, tt.want)
		}
		back := routeLess(tt.rj, tt.ri)
		if back && got {
			t.Errorf("%v. less both ways", i)
		}
	}
}

func TestRouteLessConsistent(t *testing.T) {
	for i := 0; i < 10000; i++ {
		ri := randRouteData()
		rj := randRouteData()
		if routeLess(ri, rj) && routeLess(rj, ri) {
			t.Fatalf("both compare less to each other:\n\t%#v\nand\n\t%#v", ri, rj)
		}
	}
}

func equalNetIPs(a, b []*net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if netCompare(*a[i], *b[i]) != 0 {
			return false
		}
	}
	return true
}

func ipnet4(ip string, bits int) *net.IPNet {
	return &net.IPNet{
		IP:   net.ParseIP(ip),
		Mask: net.CIDRMask(bits, 32),
	}
}

// each cidr can end in "[4]" to mean To4 form.
func nets(cidrs ...string) (ret []*net.IPNet) {
	for _, s := range cidrs {
		to4 := strings.HasSuffix(s, "[4]")
		if to4 {
			s = strings.TrimSuffix(s, "[4]")
		}
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			panic(fmt.Sprintf("Bogus CIDR %q in test", s))
		}
		if to4 {
			ip = ip.To4()
		}
		ipNet.IP = ip
		ret = append(ret, ipNet)
	}
	return
}

func TestDeltaNets(t *testing.T) {
	tests := []struct {
		a, b             []*net.IPNet
		wantAdd, wantDel []*net.IPNet
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
			b:       nets("100.84.36.11/32[4]"),
			wantDel: nets("fe80::99d0:ec2d:b2e7:536b/64"),
		},
		{
			a: excludeIPv6LinkLocal(nets("100.84.36.11/32", "fe80::99d0:ec2d:b2e7:536b/64")),
			b: nets("100.84.36.11/32"),
		},
		{
			a: []*net.IPNet{
				{
					IP:   net.ParseIP("1.2.3.4"),
					Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
				},
			},
			b: []*net.IPNet{
				{
					IP:   net.ParseIP("1.2.3.4"),
					Mask: net.IPMask{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				},
			},
		},
	}
	for i, tt := range tests {
		add, del := deltaNets(tt.a, tt.b)
		if !equalNetIPs(add, tt.wantAdd) {
			t.Errorf("[%d] add:\n  got: %v\n want: %v\n", i, add, tt.wantAdd)
		}
		if !equalNetIPs(del, tt.wantDel) {
			t.Errorf("[%d] del:\n  got: %v\n want: %v\n", i, del, tt.wantDel)
		}
	}
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

func TestDeltaRouteData(t *testing.T) {
	var h0 net.IP
	h1 := net.ParseIP("99.99.99.99")
	h2 := net.ParseIP("99.99.9.99")

	a := []*winipcfg.RouteData{
		{*ipnet4("1.2.3.4", 32), h0, 1},
		{*ipnet4("1.2.3.4", 24), h1, 2},
		{*ipnet4("1.2.3.4", 24), h2, 1},
		{*ipnet4("1.2.3.5", 32), h0, 1},
	}
	b := []*winipcfg.RouteData{
		{*ipnet4("1.2.3.5", 32), h0, 1},
		{*ipnet4("1.2.3.4", 24), h1, 2},
		{*ipnet4("1.2.3.4", 24), h2, 2},
	}
	add, del := deltaRouteData(a, b)

	wantAdd := []*winipcfg.RouteData{
		{*ipnet4("1.2.3.4", 24), h2, 2},
	}
	wantDel := []*winipcfg.RouteData{
		{*ipnet4("1.2.3.4", 32), h0, 1},
		{*ipnet4("1.2.3.4", 24), h2, 1},
	}

	if !equalRouteDatas(add, wantAdd) {
		t.Errorf("add:\n   got: %v\n  want: %v\n", add, wantAdd)
	}
	if !equalRouteDatas(del, wantDel) {
		t.Errorf("del:\n   got: %v\n  want: %v\n", del, wantDel)
	}
}

// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"math/rand"
	"net"
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

// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"math/rand"
	"net"
	"testing"

	winipcfg "github.com/tailscale/winipcfg-go"
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
	for i := 0; i < 10000; i++ {
		ri := randRouteData()
		rj := randRouteData()
		if routeLess(ri, rj) && routeLess(rj, ri) {
			t.Fatalf("both compare less to each other:\n\t%#v\nand\n\t%#v", ri, rj)
		}
	}
}

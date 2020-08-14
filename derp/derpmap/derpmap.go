// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package derpmap contains information about Tailscale.com's production DERP nodes.
package derpmap

import (
	"fmt"
	"strings"

	"tailscale.com/tailcfg"
)

func derpNode(suffix, v4, v6 string) *tailcfg.DERPNode {
	return &tailcfg.DERPNode{
		Name:     suffix, // updated later
		RegionID: 0,      // updated later
		IPv4:     v4,
		IPv6:     v6,
	}
}

func derpRegion(id int, code, name string, nodes ...*tailcfg.DERPNode) *tailcfg.DERPRegion {
	region := &tailcfg.DERPRegion{
		RegionID:   id,
		RegionName: name,
		RegionCode: code,
		Nodes:      nodes,
	}
	for _, n := range nodes {
		n.Name = fmt.Sprintf("%d%s", id, n.Name)
		n.RegionID = id
		n.HostName = fmt.Sprintf("derp%s.tailscale.com", strings.TrimSuffix(n.Name, "a"))
	}
	return region
}

// Prod returns Tailscale's map of relay servers.
//
// This list is only used by cmd/tailscale's netcheck subcommand. In
// normal operation the Tailscale nodes get this sent to them from the
// control server.
//
// This list is subject to change and should not be relied on.
func Prod() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: derpRegion(1, "nyc", "New York City",
				derpNode("a", "159.89.225.99", "2604:a880:400:d1::828:b001"),
			),
			2: derpRegion(2, "sfo", "San Francisco",
				derpNode("a", "167.172.206.31", "2604:a880:2:d1::c5:7001"),
			),
			3: derpRegion(3, "sin", "Singapore",
				derpNode("a", "68.183.179.66", "2400:6180:0:d1::67d:8001"),
			),
			4: derpRegion(4, "fra", "Frankfurt",
				derpNode("a", "167.172.182.26", "2a03:b0c0:3:e0::36e:9001"),
			),
			5: derpRegion(5, "syd", "Sydney",
				derpNode("a", "103.43.75.49", "2001:19f0:5801:10b7:5400:2ff:feaa:284c"),
			),
			6: derpRegion(6, "blr", "Bangalore",
				derpNode("a", "68.183.90.120", "2400:6180:100:d0::982:d001"),
			),
			7: derpRegion(7, "tok", "Tokyo",
				derpNode("a", "167.179.89.145", "2401:c080:1000:467f:5400:2ff:feee:22aa"),
			),
		},
	}
}

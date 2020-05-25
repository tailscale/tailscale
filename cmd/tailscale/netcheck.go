// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/derp/derpmap"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netcheck"
	"tailscale.com/types/logger"
)

var netcheckCmd = &ffcli.Command{
	Name:       "netcheck",
	ShortUsage: "netcheck",
	ShortHelp:  "Print an analysis of local network conditions",
	Exec:       runNetcheck,
}

func runNetcheck(ctx context.Context, args []string) error {
	c := &netcheck.Client{
		Logf:     logger.WithPrefix(log.Printf, "netcheck: "),
		DNSCache: dnscache.Get(),
	}

	dm := derpmap.Prod()
	report, err := c.GetReport(ctx, dm)
	if err != nil {
		log.Fatalf("netcheck: %v", err)
	}
	fmt.Printf("\nReport:\n")
	fmt.Printf("\t* UDP: %v\n", report.UDP)
	if report.GlobalV4 != "" {
		fmt.Printf("\t* IPv4: yes, %v\n", report.GlobalV4)
	} else {
		fmt.Printf("\t* IPv4: (no addr found)\n")
	}
	if report.GlobalV6 != "" {
		fmt.Printf("\t* IPv6: yes, %v\n", report.GlobalV6)
	} else if report.IPv6 {
		fmt.Printf("\t* IPv6: (no addr found)\n")
	} else {
		fmt.Printf("\t* IPv6: no\n")
	}
	fmt.Printf("\t* MappingVariesByDestIP: %v\n", report.MappingVariesByDestIP)
	fmt.Printf("\t* HairPinning: %v\n", report.HairPinning)

	// When DERP latency checking failed,
	// magicsock will try to pick the DERP server that
	// most of your other nodes are also using
	if len(report.RegionLatency) == 0 {
		fmt.Printf("\t* Nearest DERP: unknown (no response to latency probes)\n")
	} else {
		fmt.Printf("\t* Nearest DERP: %v (%v)\n", report.PreferredDERP, dm.Regions[report.PreferredDERP].RegionCode)
		fmt.Printf("\t* DERP latency:\n")
		var rids []int
		for rid := range dm.Regions {
			rids = append(rids, rid)
		}
		sort.Ints(rids)
		for _, rid := range rids {
			d, ok := report.RegionLatency[rid]
			var latency string
			if ok {
				latency = d.Round(time.Millisecond / 10).String()
			}
			fmt.Printf("\t\t- %v, %3s = %s\n", rid, dm.Regions[rid].RegionCode, latency)
		}
	}
	return nil
}

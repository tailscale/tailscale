// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main // import "tailscale.com/cmd/tailscale"

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"tailscale.com/derp/derpmap"
	"tailscale.com/net/dnscache"
	"tailscale.com/netcheck"
)

func runNetcheck(ctx context.Context, args []string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	c := &netcheck.Client{
		DERP:     derpmap.Prod(),
		Logf:     log.Printf,
		DNSCache: dnscache.Get(),
	}

	report, err := c.GetReport(ctx)
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
	fmt.Printf("\t* Nearest DERP: %v (%v)\n", report.PreferredDERP, c.DERP.LocationOfID(report.PreferredDERP))
	fmt.Printf("\t* DERP latency:\n")
	var ss []string
	for s := range report.DERPLatency {
		ss = append(ss, s)
	}
	sort.Strings(ss)
	for _, s := range ss {
		fmt.Printf("\t\t- %s = %v\n", s, report.DERPLatency[s])
	}
	return nil
}

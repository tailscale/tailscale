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

	"github.com/pborman/getopt/v2"
	"tailscale.com/netcheck"
)

func isSubcommand(cmd string) bool {
	return len(getopt.Args()) == 1 && getopt.Args()[0] == cmd
}

func netcheckCmd() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report, err := netcheck.GetReport(ctx, log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nReport:\n")
	fmt.Printf("\t* UDP: %v\n", report.UDP)
	fmt.Printf("\t* IPv6: %v\n", report.IPv6)
	fmt.Printf("\t* MappingVariesByDestIP: %v\n", report.MappingVariesByDestIP)
	fmt.Printf("\t* DERP latency:\n")
	var ss []string
	for s := range report.DERPLatency {
		ss = append(ss, s)
	}
	sort.Strings(ss)
	for _, s := range ss {
		fmt.Printf("\t\t- %s = %v\n", s, report.DERPLatency[s])
	}
}

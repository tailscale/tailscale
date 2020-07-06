// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/derp/derpmap"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netcheck"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

var netcheckCmd = &ffcli.Command{
	Name:       "netcheck",
	ShortUsage: "netcheck",
	ShortHelp:  "Print an analysis of local network conditions",
	Exec:       runNetcheck,
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("netcheck", flag.ExitOnError)
		fs.StringVar(&netcheckArgs.format, "format", "", `output format; empty (for human-readable), "json" or "json-line"`)
		fs.DurationVar(&netcheckArgs.every, "every", 0, "if non-zero, do an incremental report with the given frequency")
		fs.BoolVar(&netcheckArgs.verbose, "verbose", false, "verbose logs")
		return fs
	})(),
}

var netcheckArgs struct {
	format  string
	every   time.Duration
	verbose bool
}

func runNetcheck(ctx context.Context, args []string) error {
	c := &netcheck.Client{
		DNSCache: dnscache.Get(),
	}
	if netcheckArgs.verbose {
		c.Logf = logger.WithPrefix(log.Printf, "netcheck: ")
		c.Verbose = true
	} else {
		c.Logf = logger.Discard
	}

	if strings.HasPrefix(netcheckArgs.format, "json") {
		fmt.Fprintln(os.Stderr, "# Warning: this JSON format is not yet considered a stable interface")
	}

	dm := derpmap.Prod()
	for {
		t0 := time.Now()
		report, err := c.GetReport(ctx, dm)
		d := time.Since(t0)
		if netcheckArgs.verbose {
			c.Logf("GetReport took %v; err=%v", d.Round(time.Millisecond), err)
		}
		if err != nil {
			log.Fatalf("netcheck: %v", err)
		}
		if err := printReport(dm, report); err != nil {
			return err
		}
		if netcheckArgs.every == 0 {
			return nil
		}
		time.Sleep(netcheckArgs.every)
	}
}

func printReport(dm *tailcfg.DERPMap, report *netcheck.Report) error {
	var j []byte
	var err error
	switch netcheckArgs.format {
	case "":
		break
	case "json":
		j, err = json.MarshalIndent(report, "", "\t")
	case "json-line":
		j, err = json.Marshal(report)
	default:
		return fmt.Errorf("unknown output format %q", netcheckArgs.format)
	}
	if err != nil {
		return err
	}
	if j != nil {
		j = append(j, '\n')
		os.Stdout.Write(j)
		return nil
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
	fmt.Printf("\t* PortMapping: %v\n", portMapping(report))

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

func portMapping(r *netcheck.Report) string {
	if !r.AnyPortMappingChecked() {
		return "not checked"
	}
	var got []string
	if r.UPnP.EqualBool(true) {
		got = append(got, "UPnP")
	}
	if r.PMP.EqualBool(true) {
		got = append(got, "NAT-PMP")
	}
	if r.PCP.EqualBool(true) {
		got = append(got, "PCP")
	}
	return strings.Join(got, ", ")
}

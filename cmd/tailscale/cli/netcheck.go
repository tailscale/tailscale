// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper"
	"tailscale.com/net/tlsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

var netcheckCmd = &ffcli.Command{
	Name:       "netcheck",
	ShortUsage: "tailscale netcheck",
	ShortHelp:  "Print an analysis of local network conditions",
	Exec:       runNetcheck,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("netcheck")
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
	logf := logger.WithPrefix(log.Printf, "portmap: ")
	netMon, err := netmon.New(logf)
	if err != nil {
		return err
	}

	// Ensure that we close the portmapper after running a netcheck; this
	// will release any port mappings created.
	pm := portmapper.NewClient(logf, netMon, nil, nil, nil)
	defer pm.Close()

	c := &netcheck.Client{
		NetMon:      netMon,
		PortMapper:  pm,
		UseDNSCache: false, // always resolve, don't cache
	}
	if netcheckArgs.verbose {
		c.Logf = logger.WithPrefix(log.Printf, "netcheck: ")
		c.Verbose = true
	} else {
		c.Logf = logger.Discard
	}

	if strings.HasPrefix(netcheckArgs.format, "json") {
		fmt.Fprintln(Stderr, "# Warning: this JSON format is not yet considered a stable interface")
	}

	if err := c.Standalone(ctx, envknob.String("TS_DEBUG_NETCHECK_UDP_BIND")); err != nil {
		fmt.Fprintln(Stderr, "netcheck: UDP test failure:", err)
	}

	dm, err := localClient.CurrentDERPMap(ctx)
	noRegions := dm != nil && len(dm.Regions) == 0
	if noRegions {
		log.Printf("No DERP map from tailscaled; using default.")
	}
	if err != nil || noRegions {
		hc := &http.Client{
			Transport: tlsdial.NewTransport(),
			Timeout:   10 * time.Second,
		}
		dm, err = prodDERPMap(ctx, hc)
		if err != nil {
			log.Println("Failed to fetch a DERP map, so netcheck cannot continue. Check your Internet connection.")
			return err
		}
	}
	for {
		t0 := time.Now()
		report, err := c.GetReport(ctx, dm, nil)
		d := time.Since(t0)
		if netcheckArgs.verbose {
			c.Logf("GetReport took %v; err=%v", d.Round(time.Millisecond), err)
		}
		if err != nil {
			return fmt.Errorf("netcheck: %w", err)
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
		Stdout.Write(j)
		return nil
	}

	printf("\nReport:\n")
	printf("\t* Time: %v\n", report.Now.Format(time.RFC3339Nano))
	printf("\t* UDP: %v\n", report.UDP)
	if report.GlobalV4.IsValid() {
		printf("\t* IPv4: yes, %s\n", report.GlobalV4)
	} else {
		printf("\t* IPv4: (no addr found)\n")
	}
	if report.GlobalV6.IsValid() {
		printf("\t* IPv6: yes, %s\n", report.GlobalV6)
	} else if report.IPv6 {
		printf("\t* IPv6: (no addr found)\n")
	} else if report.OSHasIPv6 {
		printf("\t* IPv6: no, but OS has support\n")
	} else {
		printf("\t* IPv6: no, unavailable in OS\n")
	}
	printf("\t* MappingVariesByDestIP: %v\n", report.MappingVariesByDestIP)
	printf("\t* PortMapping: %v\n", portMapping(report))
	if report.CaptivePortal != "" {
		printf("\t* CaptivePortal: %v\n", report.CaptivePortal)
	}

	// When DERP latency checking failed,
	// magicsock will try to pick the DERP server that
	// most of your other nodes are also using
	if len(report.RegionLatency) == 0 {
		printf("\t* Nearest DERP: unknown (no response to latency probes)\n")
	} else {
		if report.PreferredDERP != 0 {
			printf("\t* Nearest DERP: %v\n", dm.Regions[report.PreferredDERP].RegionName)
		} else {
			printf("\t* Nearest DERP: [none]\n")
		}
		printf("\t* DERP latency:\n")
		var rids []int
		for rid := range dm.Regions {
			rids = append(rids, rid)
		}
		sort.Slice(rids, func(i, j int) bool {
			l1, ok1 := report.RegionLatency[rids[i]]
			l2, ok2 := report.RegionLatency[rids[j]]
			if ok1 != ok2 {
				return ok1 // defined things sort first
			}
			if !ok1 {
				return rids[i] < rids[j]
			}
			return l1 < l2
		})
		for _, rid := range rids {
			d, ok := report.RegionLatency[rid]
			var latency string
			if ok {
				latency = d.Round(time.Millisecond / 10).String()
			}
			r := dm.Regions[rid]
			var derpNum string
			if netcheckArgs.verbose {
				derpNum = fmt.Sprintf("derp%d, ", rid)
			}
			printf("\t\t- %3s: %-7s (%s%s)\n", r.RegionCode, latency, derpNum, r.RegionName)
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

func prodDERPMap(ctx context.Context, httpc *http.Client) (*tailcfg.DERPMap, error) {
	log.Printf("attempting to fetch a DERPMap from %s", ipn.DefaultControlURL)
	req, err := http.NewRequestWithContext(ctx, "GET", ipn.DefaultControlURL+"/derpmap/default", nil)
	if err != nil {
		return nil, fmt.Errorf("create prodDERPMap request: %w", err)
	}
	res, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch prodDERPMap failed: %w", err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("fetch prodDERPMap failed: %w", err)
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("fetch prodDERPMap: %v: %s", res.Status, b)
	}
	var derpMap tailcfg.DERPMap
	if err = json.Unmarshal(b, &derpMap); err != nil {
		return nil, fmt.Errorf("fetch prodDERPMap: %w", err)
	}
	return &derpMap, nil
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/envknob"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper/portmappertype"
	"tailscale.com/net/tlsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/set"

	// The "nattype" command also wants the portmapper linked.
	_ "tailscale.com/feature/condregister/portmapper"
)

var nattypeCmd = &ffcli.Command{
	Name:       "nattype",
	ShortUsage: "tailscale nattype [--json] [--format=json|json-line]",
	ShortHelp:  "Classify local NAT behavior for peer connectivity",
	Exec:       runNATType,
	FlagSet:    nattypeFlagSet,
}

var nattypeFlagSet = func() *flag.FlagSet {
	fs := newFlagSet("nattype")
	fs.BoolVar(&nattypeArgs.json, "json", false, "output in JSON format (equivalent to --format=json)")
	fs.StringVar(&nattypeArgs.format, "format", "", `output format; empty (for human-readable), "json" or "json-line"`)
	fs.BoolVar(&nattypeArgs.verbose, "verbose", false, "verbose logs")
	fs.StringVar(&nattypeArgs.bindAddress, "bind-address", "", "send and receive connectivity probes using this locally bound IP address; default: OS-assigned")
	fs.IntVar(&nattypeArgs.bindPort, "bind-port", 0, "send and receive connectivity probes using this UDP port; default: OS-assigned")
	return fs
}()

var nattypeArgs struct {
	json        bool
	format      string
	verbose     bool
	bindAddress string
	bindPort    int
}

const (
	natTypeUDPBlocked                     = "UDP Blocked"
	natTypeNoNAT                          = "No NAT"
	natTypeEndpointIndependentMapping     = "Endpoint-Independent Mapping"
	natTypeAddressDependentMapping        = "Address-Dependent Mapping"
	natTypeAddressAndPortDependentMapping = "Address and Port-Dependent Mapping"
)

type natTypeDetail struct {
	Difficulty        string
	DirectConnections string
}

type natTypeResult struct {
	Time                  time.Time
	NATType               string
	Difficulty            string
	DirectConnections     string
	Summary               string
	Details               string `json:",omitempty"`
	UDP                   bool
	MappingVariesByDestIP opt.Bool `json:",omitzero"`
	PortMapping           string
	LocalV4               netip.Addr
	GlobalV4              netip.AddrPort
	GlobalV6              netip.AddrPort
	NetcheckReport        *netcheck.Report
}

func runNATType(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unexpected non-flag arguments to 'tailscale nattype'")
	}

	format := nattypeArgs.format
	if nattypeArgs.json {
		if format != "" && format != "json" {
			return fmt.Errorf("cannot use --json with --format=%q", format)
		}
		format = "json"
	}

	logf := logger.Discard
	if nattypeArgs.verbose {
		logf = logger.WithPrefix(log.Printf, "portmap: ")
	}
	bus := eventbus.New()
	defer bus.Close()
	netMon, err := netmon.New(bus, logf)
	if err != nil {
		return err
	}

	var pm portmappertype.Client
	if buildfeatures.HasPortMapper {
		pm = portmappertype.HookNewPortMapper.Get()(logf, bus, netMon, nil, nil)
		defer pm.Close()
	}

	flagsProvided := set.Set[string]{}
	nattypeFlagSet.Visit(func(f *flag.Flag) {
		flagsProvided.Add(f.Name)
	})

	c := &netcheck.Client{
		NetMon:      netMon,
		PortMapper:  pm,
		UseDNSCache: false,
	}
	if nattypeArgs.verbose {
		c.Logf = logger.WithPrefix(log.Printf, "netcheck: ")
		c.Verbose = true
	} else {
		c.Logf = logger.Discard
	}

	if strings.HasPrefix(format, "json") {
		fmt.Fprintln(Stderr, "# Warning: this JSON format is not yet considered a stable interface")
	}

	bind, err := createNetcheckBindString(
		nattypeArgs.bindAddress,
		flagsProvided.Contains("bind-address"),
		nattypeArgs.bindPort,
		flagsProvided.Contains("bind-port"),
		envknob.String("TS_DEBUG_NETCHECK_UDP_BIND"))
	if err != nil {
		return err
	}

	if err := c.Standalone(ctx, bind); err != nil {
		fmt.Fprintln(Stderr, "nattype: UDP test failure:", err)
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
			log.Println("Failed to fetch a DERP map, so nattype cannot continue. Check your Internet connection.")
			return err
		}
	}

	report, err := c.GetReport(ctx, dm, nil)
	if err != nil {
		return fmt.Errorf("nattype: %w", err)
	}

	localV4 := localIPv4ForDERPMap(ctx, dm)
	natType := classifyNATType(report, localV4)
	detail := natTypeDetailFor(natType)
	portMapping := natPortMapping(report)
	summary := natTypeSummaryFor(natType)
	details := ""
	mappingVariesByDestIP := opt.Bool("")
	if nattypeArgs.verbose {
		details = natTypeTechnicalDetailsFor(natType, report, localV4, portMapping)
		mappingVariesByDestIP = report.MappingVariesByDestIP
	}
	result := natTypeResult{
		Time:                  report.Now,
		NATType:               natType,
		Difficulty:            detail.Difficulty,
		DirectConnections:     detail.DirectConnections,
		Summary:               summary,
		Details:               details,
		UDP:                   report.UDP,
		MappingVariesByDestIP: mappingVariesByDestIP,
		PortMapping:           portMapping,
		LocalV4:               localV4,
		GlobalV4:              report.GlobalV4,
		GlobalV6:              report.GlobalV6,
		NetcheckReport:        report,
	}
	return printNATTypeResult(result, format)
}

func printNATTypeResult(result natTypeResult, format string) error {
	var j []byte
	var err error
	switch format {
	case "":
	case "json":
		j, err = json.MarshalIndent(result, "", "\t")
	case "json-line":
		j, err = json.Marshal(result)
	default:
		return fmt.Errorf("unknown output format %q", format)
	}
	if err != nil {
		return err
	}
	if j != nil {
		j = append(j, '\n')
		Stdout.Write(j)
		return nil
	}

	printf("\nNAT Type Report:\n")
	printf("\t* Time: %v\n", result.Time.Format(time.RFC3339Nano))
	printf("\t* NAT Type: %s\n", result.NATType)
	printf("\t* Difficulty: %s\n", result.Difficulty)
	printf("\t* Direct Connections: %s\n", result.DirectConnections)
	printf("\t* UDP: %v\n", result.UDP)
	if nattypeArgs.verbose {
		printf("\t* MappingVariesByDestIP: %s\n", formatOptionalBool(result.MappingVariesByDestIP))
	}
	printf("\t* PortMapping: %s\n", result.PortMapping)
	if result.LocalV4.IsValid() {
		printf("\t* LocalIPv4: %s\n", result.LocalV4)
	}
	if result.GlobalV4.IsValid() {
		printf("\t* ExternalIPv4: %s\n", result.GlobalV4)
	} else {
		printf("\t* ExternalIPv4: (no addr found)\n")
	}
	if result.GlobalV6.IsValid() {
		printf("\t* ExternalIPv6: %s\n", result.GlobalV6)
	}
	printf("\t* Summary: %s\n", result.Summary)
	if nattypeArgs.verbose && result.Details != "" {
		printf("\t* Details: %s\n", result.Details)
	}
	return nil
}

func natPortMapping(report *netcheck.Report) string {
	p := portMapping(report)
	if p == "" {
		return "None"
	}
	return p
}

func classifyNATType(report *netcheck.Report, localV4 netip.Addr) string {
	if report == nil || !report.UDP {
		return natTypeUDPBlocked
	}
	if localV4.IsValid() && report.GlobalV4.IsValid() && report.GlobalV4.Addr() == localV4 {
		return natTypeNoNAT
	}
	if report.MappingVariesByDestIP.EqualBool(true) {
		return natTypeAddressAndPortDependentMapping
	}
	if report.MappingVariesByDestIP.EqualBool(false) {
		return natTypeEndpointIndependentMapping
	}
	return natTypeAddressDependentMapping
}

func natTypeDetailFor(natType string) natTypeDetail {
	switch natType {
	case natTypeUDPBlocked:
		return natTypeDetail{
			Difficulty:        "Hard",
			DirectConnections: "None (blocked)",
		}
	case natTypeNoNAT:
		return natTypeDetail{
			Difficulty:        "None",
			DirectConnections: "All devices",
		}
	case natTypeEndpointIndependentMapping:
		return natTypeDetail{
			Difficulty:        "Easy",
			DirectConnections: "Easy NAT + No NAT devices",
		}
	case natTypeAddressDependentMapping:
		return natTypeDetail{
			Difficulty:        "Easy",
			DirectConnections: "Easy NAT + No NAT devices",
		}
	case natTypeAddressAndPortDependentMapping:
		return natTypeDetail{
			Difficulty:        "Hard",
			DirectConnections: "No NAT devices only",
		}
	default:
		return natTypeDetail{
			Difficulty:        "Unknown",
			DirectConnections: "Unknown",
		}
	}
}

func natTypeSummaryFor(natType string) string {
	switch natType {
	case natTypeUDPBlocked:
		return "UDP appears blocked. Expect most direct peer connections to fail and rely on relays."
	case natTypeNoNAT:
		return "You appear to be on a public IP with no NAT. Expect direct peer connections to work broadly."
	case natTypeEndpointIndependentMapping:
		return "Your NAT is generally P2P-friendly. Expect direct peer connections to work in most cases."
	case natTypeAddressDependentMapping:
		return "Your NAT is moderately restrictive. Expect many direct connections, with some relay fallback."
	case natTypeAddressAndPortDependentMapping:
		return "Your NAT is strict and destination-dependent. Expect more relay usage, especially with other strict NAT peers."
	default:
		return "NAT behavior was not conclusive. Expect mixed direct vs relay connectivity."
	}
}

func natTypeTechnicalDetailsFor(natType string, report *netcheck.Report, localV4 netip.Addr, portMapping string) string {
	if report == nil {
		return "No netcheck report was available, so NAT classification could not use runtime measurements."
	}

	var reasons []string
	switch natType {
	case natTypeUDPBlocked:
		reasons = append(reasons, "Classified as UDP Blocked because no UDP STUN round-trip completed.")
	case natTypeNoNAT:
		if localV4.IsValid() && report.GlobalV4.IsValid() {
			reasons = append(reasons, fmt.Sprintf("Classified as No NAT because local IPv4 %s matched observed external IPv4 %s.", localV4, report.GlobalV4.Addr()))
		} else {
			reasons = append(reasons, "Classified as No NAT based on local/external address comparison during STUN checks.")
		}
	case natTypeAddressAndPortDependentMapping:
		reasons = append(reasons, "Classified as Address and Port-Dependent Mapping because STUN observed different external IPv4 endpoints for different destinations.")
		if ev := mappingEvidence(report); ev != "" {
			reasons = append(reasons, ev)
		}
	case natTypeEndpointIndependentMapping:
		reasons = append(reasons, "Classified as Endpoint-Independent Mapping because repeated STUN checks reported a consistent external IPv4 endpoint across destinations.")
		if ev := mappingEvidence(report); ev != "" {
			reasons = append(reasons, ev)
		}
	case natTypeAddressDependentMapping:
		reasons = append(reasons, "Classified as Address-Dependent Mapping as a conservative fallback: UDP worked, but destination-based mapping variation was not conclusively measured.")
		if ev := mappingEvidence(report); ev != "" {
			reasons = append(reasons, ev)
		}
	default:
		reasons = append(reasons, "Classification used available STUN and port-mapping signals, but they were not conclusive.")
	}

	if portMapping == "None" || portMapping == "not checked" {
		reasons = append(reasons, "No UPnP/NAT-PMP/PCP assistance was detected.")
	} else {
		reasons = append(reasons, fmt.Sprintf("Detected LAN port-mapping support: %s.", portMapping))
	}
	return strings.Join(reasons, " ")
}

func mappingEvidence(report *netcheck.Report) string {
	if len(report.GlobalV4Counters) == 0 {
		return ""
	}

	type endpointCount struct {
		endpoint netip.AddrPort
		count    int
	}
	var pairs []endpointCount
	for ep, cnt := range report.GlobalV4Counters {
		pairs = append(pairs, endpointCount{endpoint: ep, count: cnt})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].endpoint.String() < pairs[j].endpoint.String()
	})

	limit := 3
	if len(pairs) < limit {
		limit = len(pairs)
	}
	var top []string
	for i := 0; i < limit; i++ {
		top = append(top, fmt.Sprintf("%s (%dx)", pairs[i].endpoint, pairs[i].count))
	}

	return fmt.Sprintf("Observed %d external IPv4 endpoint(s): %s.", len(pairs), strings.Join(top, ", "))
}

func formatOptionalBool(v opt.Bool) string {
	if v.EqualBool(true) {
		return "true"
	}
	if v.EqualBool(false) {
		return "false"
	}
	return "unknown"
}

func localIPv4ForDERPMap(ctx context.Context, dm *tailcfg.DERPMap) netip.Addr {
	if dm == nil {
		return netip.Addr{}
	}

	const maxDialAttempts = 3
	dialAttempts := 0

	var regionIDs []int
	for rid := range dm.Regions {
		regionIDs = append(regionIDs, rid)
	}
	sort.Ints(regionIDs)

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	for _, rid := range regionIDs {
		region := dm.Regions[rid]
		for _, node := range region.Nodes {
			if node == nil || node.STUNPort < 0 {
				continue
			}

			host := node.HostName
			if ip := net.ParseIP(node.IPv4); ip != nil && ip.To4() != nil {
				host = node.IPv4
			}
			if host == "" {
				continue
			}
			port := node.STUNPort
			if port == 0 {
				port = 3478
			}

			dialAttempts++
			if dialAttempts > maxDialAttempts {
				return netip.Addr{}
			}

			conn, err := dialer.DialContext(ctx, "udp4", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				continue
			}
			laddr, ok := conn.LocalAddr().(*net.UDPAddr)
			conn.Close()
			if !ok {
				continue
			}
			if addr, ok := netip.AddrFromSlice(laddr.IP); ok {
				return addr.Unmap()
			}
		}
	}
	return netip.Addr{}
}

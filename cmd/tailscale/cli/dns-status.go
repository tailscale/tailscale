// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/netmap"
)

// DNSResolverInfo describes a DNS resolver address and optional bootstrap
// resolution addresses.
type DNSResolverInfo struct {
	Addr                string
	BootstrapResolution []string `json:",omitempty"`
}

// DNSExtraRecord describes an additional DNS record provided by the
// coordination server to the internal DNS resolver.
type DNSExtraRecord struct {
	Name  string
	Type  string `json:",omitempty"`
	Value string
}

// DNSSystemConfig describes the operating system's DNS configuration
// as observed by Tailscale.
type DNSSystemConfig struct {
	Nameservers   []string
	SearchDomains []string
	MatchDomains  []string
}

// DNSTailnetInfo describes the MagicDNS configuration for the current tailnet.
type DNSTailnetInfo struct {
	MagicDNSEnabled bool
	MagicDNSSuffix  string `json:",omitempty"`
	SelfDNSName     string `json:",omitempty"`
}

// DNSStatusResult contains the full DNS status and configuration collected
// from the local Tailscale daemon.
type DNSStatusResult struct {
	TailscaleDNS        bool
	CurrentTailnet      *DNSTailnetInfo `json:",omitzero"`
	Resolvers           []DNSResolverInfo
	SplitDNSRoutes      map[string][]DNSResolverInfo
	FallbackResolvers   []DNSResolverInfo
	SearchDomains       []string
	Nameservers         []string
	CertDomains         []string
	ExtraRecords        []DNSExtraRecord
	ExitNodeFilteredSet []string
	SystemDNS           *DNSSystemConfig `json:",omitzero"`
	SystemDNSError      string           `json:",omitempty"`
}

var dnsStatusCmd = &ffcli.Command{
	Name:       "status",
	ShortUsage: "tailscale dns status [--all] [--json]",
	Exec:       runDNSStatus,
	ShortHelp:  "Print the current DNS status and configuration",
	LongHelp: strings.TrimSpace(`
The 'tailscale dns status' subcommand prints the current DNS status and
configuration, including:

- Whether the built-in DNS forwarder is enabled.

- The MagicDNS configuration provided by the coordination server.

- Details on which resolver(s) Tailscale believes the system is using by
  default.

The --all flag can be used to output advanced debugging information, including
fallback resolvers, nameservers, certificate domains, extra records, and the
exit node filtered set.

=== Contents of the MagicDNS configuration ===

The MagicDNS configuration is provided by the coordination server to the client
and includes the following components:

- MagicDNS enablement status: Indicates whether MagicDNS is enabled across the
  entire tailnet.

- MagicDNS Suffix: The DNS suffix used for devices within your tailnet.

- DNS Name: The DNS name that other devices in the tailnet can use to reach this
  device.

- Resolvers: The preferred DNS resolver(s) to be used for resolving queries, in
  order of preference. If no resolvers are listed here, the system defaults are
  used.

- Split DNS Routes: Custom DNS resolvers may be used to resolve hostnames in
  specific domains, this is also known as a 'Split DNS' configuration. The
  mapping of domains to their respective resolvers is provided here.

- Certificate Domains: The DNS names for which the coordination server will
  assist in provisioning TLS certificates.

- Extra Records: Additional DNS records that the coordination server might
  provide to the internal DNS resolver.

- Exit Node Filtered Set: DNS suffixes that the node, when acting as an exit
  node DNS proxy, will not answer.

For more information about the DNS functionality built into Tailscale, refer to
https://tailscale.com/kb/1054/dns.
`),
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("status")
		fs.BoolVar(&dnsStatusArgs.all, "all", false, "outputs advanced debugging information")
		fs.BoolVar(&dnsStatusArgs.json, "json", false, "output in JSON format")
		return fs
	})(),
}

// dnsStatusArgs are the arguments for the "dns status" subcommand.
var dnsStatusArgs struct {
	all  bool
	json bool
}

// makeDNSResolverInfo converts a dnstype.Resolver to a DNSResolverInfo.
func makeDNSResolverInfo(r *dnstype.Resolver) DNSResolverInfo {
	info := DNSResolverInfo{Addr: r.Addr}
	if r.BootstrapResolution != nil {
		info.BootstrapResolution = make([]string, 0, len(r.BootstrapResolution))
		for _, a := range r.BootstrapResolution {
			info.BootstrapResolution = append(info.BootstrapResolution, a.String())
		}
	}
	return info
}

func runDNSStatus(ctx context.Context, args []string) error {
	s, err := localClient.Status(ctx)
	if err != nil {
		return err
	}

	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}

	data := &DNSStatusResult{
		TailscaleDNS: prefs.CorpDNS,
	}

	if s.CurrentTailnet != nil {
		data.CurrentTailnet = &DNSTailnetInfo{
			MagicDNSEnabled: s.CurrentTailnet.MagicDNSEnabled,
			MagicDNSSuffix:  s.CurrentTailnet.MagicDNSSuffix,
			SelfDNSName:     s.Self.DNSName,
		}

		netMap, err := fetchNetMap()
		if err != nil {
			return fmt.Errorf("failed to fetch network map: %w", err)
		}
		dnsConfig := netMap.DNS

		for _, r := range dnsConfig.Resolvers {
			data.Resolvers = append(data.Resolvers, makeDNSResolverInfo(r))
		}

		data.SplitDNSRoutes = make(map[string][]DNSResolverInfo)
		for k, v := range dnsConfig.Routes {
			for _, r := range v {
				data.SplitDNSRoutes[k] = append(data.SplitDNSRoutes[k], makeDNSResolverInfo(r))
			}
		}

		for _, r := range dnsConfig.FallbackResolvers {
			data.FallbackResolvers = append(data.FallbackResolvers, makeDNSResolverInfo(r))
		}

		domains := slices.Clone(dnsConfig.Domains)
		slices.Sort(domains)
		data.SearchDomains = domains

		for _, a := range dnsConfig.Nameservers {
			data.Nameservers = append(data.Nameservers, a.String())
		}

		data.CertDomains = dnsConfig.CertDomains

		for _, er := range dnsConfig.ExtraRecords {
			data.ExtraRecords = append(data.ExtraRecords, DNSExtraRecord{
				Name:  er.Name,
				Type:  er.Type,
				Value: er.Value,
			})
		}

		data.ExitNodeFilteredSet = dnsConfig.ExitNodeFilteredSet

		osCfg, err := localClient.GetDNSOSConfig(ctx)
		if err != nil {
			if strings.Contains(err.Error(), "not supported") {
				data.SystemDNSError = "not supported on this platform"
			} else {
				data.SystemDNSError = err.Error()
			}
		} else if osCfg != nil {
			data.SystemDNS = &DNSSystemConfig{
				Nameservers:   osCfg.Nameservers,
				SearchDomains: osCfg.SearchDomains,
				MatchDomains:  osCfg.MatchDomains,
			}
		}
	}

	if dnsStatusArgs.json {
		j, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return err
		}
		printf("%s\n", j)
		return nil
	}
	printf("%s", formatDNSStatusText(data, dnsStatusArgs.all))
	return nil
}

func formatDNSStatusText(data *DNSStatusResult, all bool) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "\n")
	fmt.Fprintf(&sb, "=== 'Use Tailscale DNS' status ===\n")
	fmt.Fprintf(&sb, "\n")
	if data.TailscaleDNS {
		fmt.Fprintf(&sb, "Tailscale DNS: enabled.\n\nTailscale is configured to handle DNS queries on this device.\nRun 'tailscale set --accept-dns=false' to revert to your system default DNS resolver.\n")
	} else {
		fmt.Fprintf(&sb, "Tailscale DNS: disabled.\n\n(Run 'tailscale set --accept-dns=true' to start sending DNS queries to the Tailscale DNS resolver)\n")
	}
	fmt.Fprintf(&sb, "\n")
	fmt.Fprintf(&sb, "=== MagicDNS configuration ===\n")
	fmt.Fprintf(&sb, "\n")
	fmt.Fprintf(&sb, "This is the DNS configuration provided by the coordination server to this device.\n")
	fmt.Fprintf(&sb, "\n")
	if data.CurrentTailnet == nil {
		fmt.Fprintf(&sb, "No tailnet information available; make sure you're logged in to a tailnet.\n")
		return sb.String()
	}

	if data.CurrentTailnet.MagicDNSEnabled {
		fmt.Fprintf(&sb, "MagicDNS: enabled tailnet-wide (suffix = %s)", data.CurrentTailnet.MagicDNSSuffix)
		fmt.Fprintf(&sb, "\n\n")
		fmt.Fprintf(&sb, "Other devices in your tailnet can reach this device at %s\n", data.CurrentTailnet.SelfDNSName)
	} else {
		fmt.Fprintf(&sb, "MagicDNS: disabled tailnet-wide.\n")
	}
	fmt.Fprintf(&sb, "\n")

	fmt.Fprintf(&sb, "Resolvers (in preference order):\n")
	if len(data.Resolvers) == 0 {
		fmt.Fprintf(&sb, "  (no resolvers configured, system default will be used: see 'System DNS configuration' below)\n")
	}
	for _, r := range data.Resolvers {
		fmt.Fprintf(&sb, "  - %v", r.Addr)
		if r.BootstrapResolution != nil {
			fmt.Fprintf(&sb, " (bootstrap: %v)", r.BootstrapResolution)
		}
		fmt.Fprintf(&sb, "\n")
	}
	fmt.Fprintf(&sb, "\n")

	fmt.Fprintf(&sb, "Split DNS Routes:\n")
	if len(data.SplitDNSRoutes) == 0 {
		fmt.Fprintf(&sb, "  (no routes configured: split DNS disabled)\n")
	}
	for _, k := range slices.Sorted(maps.Keys(data.SplitDNSRoutes)) {
		for _, r := range data.SplitDNSRoutes[k] {
			fmt.Fprintf(&sb, "  - %-30s -> %v", k, r.Addr)
			if r.BootstrapResolution != nil {
				fmt.Fprintf(&sb, " (bootstrap: %v)", r.BootstrapResolution)
			}
			fmt.Fprintf(&sb, "\n")
		}
	}
	fmt.Fprintf(&sb, "\n")

	if all {
		fmt.Fprintf(&sb, "Fallback Resolvers:\n")
		if len(data.FallbackResolvers) == 0 {
			fmt.Fprintf(&sb, "  (no fallback resolvers configured)\n")
		}
		for i, r := range data.FallbackResolvers {
			fmt.Fprintf(&sb, "  %d: %v", i, r.Addr)
			if r.BootstrapResolution != nil {
				fmt.Fprintf(&sb, " (bootstrap: %v)", r.BootstrapResolution)
			}
			fmt.Fprintf(&sb, "\n")
		}
		fmt.Fprintf(&sb, "\n")
	}

	fmt.Fprintf(&sb, "Search Domains:\n")
	if len(data.SearchDomains) == 0 {
		fmt.Fprintf(&sb, "  (no search domains configured)\n")
	}
	for _, r := range data.SearchDomains {
		fmt.Fprintf(&sb, "  - %v\n", r)
	}
	fmt.Fprintf(&sb, "\n")

	if all {
		fmt.Fprintf(&sb, "Nameservers IP Addresses:\n")
		if len(data.Nameservers) == 0 {
			fmt.Fprintf(&sb, "  (none were provided)\n")
		}
		for _, r := range data.Nameservers {
			fmt.Fprintf(&sb, "  - %v\n", r)
		}
		fmt.Fprintf(&sb, "\n")

		fmt.Fprintf(&sb, "Certificate Domains:\n")
		if len(data.CertDomains) == 0 {
			fmt.Fprintf(&sb, "  (no certificate domains are configured)\n")
		}
		for _, r := range data.CertDomains {
			fmt.Fprintf(&sb, "  - %v\n", r)
		}
		fmt.Fprintf(&sb, "\n")

		fmt.Fprintf(&sb, "Additional DNS Records:\n")
		if len(data.ExtraRecords) == 0 {
			fmt.Fprintf(&sb, "  (no extra records are configured)\n")
		}
		for _, er := range data.ExtraRecords {
			if er.Type == "" {
				fmt.Fprintf(&sb, "  - %-50s -> %v\n", er.Name, er.Value)
			} else {
				fmt.Fprintf(&sb, "  - [%s] %-50s -> %v\n", er.Type, er.Name, er.Value)
			}
		}
		fmt.Fprintf(&sb, "\n")

		fmt.Fprintf(&sb, "Filtered suffixes when forwarding DNS queries as an exit node:\n")
		if len(data.ExitNodeFilteredSet) == 0 {
			fmt.Fprintf(&sb, "  (no suffixes are filtered)\n")
		}
		for _, s := range data.ExitNodeFilteredSet {
			fmt.Fprintf(&sb, "  - %s\n", s)
		}
		fmt.Fprintf(&sb, "\n")
	}

	fmt.Fprintf(&sb, "=== System DNS configuration ===\n")
	fmt.Fprintf(&sb, "\n")
	fmt.Fprintf(&sb, "This is the DNS configuration that Tailscale believes your operating system is using.\nTailscale may use this configuration if 'Override Local DNS' is disabled in the admin console,\nor if no resolvers are provided by the coordination server.\n")
	fmt.Fprintf(&sb, "\n")

	if data.SystemDNSError != "" {
		if strings.Contains(data.SystemDNSError, "not supported") {
			fmt.Fprintf(&sb, "  (reading the system DNS configuration is not supported on this platform)\n")
		} else {
			fmt.Fprintf(&sb, "  (failed to read system DNS configuration: %s)\n", data.SystemDNSError)
		}
	} else if data.SystemDNS == nil {
		fmt.Fprintf(&sb, "  (no OS DNS configuration available)\n")
	} else {
		fmt.Fprintf(&sb, "Nameservers:\n")
		if len(data.SystemDNS.Nameservers) == 0 {
			fmt.Fprintf(&sb, "  (no nameservers found, DNS queries might fail\nunless the coordination server is providing a nameserver)\n")
		}
		for _, ns := range data.SystemDNS.Nameservers {
			fmt.Fprintf(&sb, "  - %v\n", ns)
		}
		fmt.Fprintf(&sb, "\n")
		fmt.Fprintf(&sb, "Search domains:\n")
		if len(data.SystemDNS.SearchDomains) == 0 {
			fmt.Fprintf(&sb, "  (no search domains found)\n")
		}
		for _, sd := range data.SystemDNS.SearchDomains {
			fmt.Fprintf(&sb, "  - %v\n", sd)
		}
		if all {
			fmt.Fprintf(&sb, "\n")
			fmt.Fprintf(&sb, "Match domains:\n")
			if len(data.SystemDNS.MatchDomains) == 0 {
				fmt.Fprintf(&sb, "  (no match domains found)\n")
			}
			for _, md := range data.SystemDNS.MatchDomains {
				fmt.Fprintf(&sb, "  - %v\n", md)
			}
		}
	}
	fmt.Fprintf(&sb, "\n")
	fmt.Fprintf(&sb, "[this is a preliminary version of this command; the output format may change in the future]\n")
	return sb.String()
}

func fetchNetMap() (netMap *netmap.NetworkMap, err error) {
	w, err := localClient.WatchIPNBus(context.Background(), ipn.NotifyInitialNetMap)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	notify, err := w.Next()
	if err != nil {
		return nil, err
	}
	if notify.NetMap == nil {
		return nil, fmt.Errorf("no network map yet available, please try again later")
	}
	return notify.NetMap, nil
}

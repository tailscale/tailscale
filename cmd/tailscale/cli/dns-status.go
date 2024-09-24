// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/types/netmap"
)

// dnsStatusArgs are the arguments for the "dns status" subcommand.
var dnsStatusArgs struct {
	all bool
}

func runDNSStatus(ctx context.Context, args []string) error {
	all := dnsStatusArgs.all
	s, err := localClient.Status(ctx)
	if err != nil {
		return err
	}

	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}
	enabledStr := "disabled.\n\n(Run 'tailscale set --accept-dns=true' to start sending DNS queries to the Tailscale DNS resolver)"
	if prefs.CorpDNS {
		enabledStr = "enabled.\n\nTailscale is configured to handle DNS queries on this device.\nRun 'tailscale set --accept-dns=false' to revert to your system default DNS resolver."
	}
	fmt.Print("\n")
	fmt.Println("=== 'Use Tailscale DNS' status ===")
	fmt.Print("\n")
	fmt.Printf("Tailscale DNS: %s\n", enabledStr)
	fmt.Print("\n")
	fmt.Println("=== MagicDNS configuration ===")
	fmt.Print("\n")
	fmt.Println("This is the DNS configuration provided by the coordination server to this device.")
	fmt.Print("\n")
	if s.CurrentTailnet == nil {
		fmt.Println("No tailnet information available; make sure you're logged in to a tailnet.")
		return nil
	} else if s.CurrentTailnet.MagicDNSEnabled {
		fmt.Printf("MagicDNS: enabled tailnet-wide (suffix = %s)", s.CurrentTailnet.MagicDNSSuffix)
		fmt.Print("\n\n")
		fmt.Printf("Other devices in your tailnet can reach this device at %s\n", s.Self.DNSName)
	} else {
		fmt.Printf("MagicDNS: disabled tailnet-wide.\n")
	}
	fmt.Print("\n")

	netMap, err := fetchNetMap()
	if err != nil {
		fmt.Printf("Failed to fetch network map: %v\n", err)
		return err
	}
	dnsConfig := netMap.DNS
	fmt.Println("Resolvers (in preference order):")
	if len(dnsConfig.Resolvers) == 0 {
		fmt.Println("  (no resolvers configured, system default will be used: see 'System DNS configuration' below)")
	}
	for _, r := range dnsConfig.Resolvers {
		fmt.Printf("  - %v", r.Addr)
		if r.BootstrapResolution != nil {
			fmt.Printf(" (bootstrap: %v)", r.BootstrapResolution)
		}
		fmt.Print("\n")
	}
	fmt.Print("\n")
	fmt.Println("Split DNS Routes:")
	if len(dnsConfig.Routes) == 0 {
		fmt.Println("  (no routes configured: split DNS disabled)")
	}
	for _, k := range slices.Sorted(maps.Keys(dnsConfig.Routes)) {
		v := dnsConfig.Routes[k]
		for _, r := range v {
			fmt.Printf("  - %-30s -> %v", k, r.Addr)
			if r.BootstrapResolution != nil {
				fmt.Printf(" (bootstrap: %v)", r.BootstrapResolution)
			}
			fmt.Print("\n")
		}
	}
	fmt.Print("\n")
	if all {
		fmt.Println("Fallback Resolvers:")
		if len(dnsConfig.FallbackResolvers) == 0 {
			fmt.Println("  (no fallback resolvers configured)")
		}
		for i, r := range dnsConfig.FallbackResolvers {
			fmt.Printf("  %d: %v\n", i, r)
		}
		fmt.Print("\n")
	}
	fmt.Println("Search Domains:")
	if len(dnsConfig.Domains) == 0 {
		fmt.Println("  (no search domains configured)")
	}
	domains := dnsConfig.Domains
	slices.Sort(domains)
	for _, r := range domains {
		fmt.Printf("  - %v\n", r)
	}
	fmt.Print("\n")
	if all {
		fmt.Println("Nameservers IP Addresses:")
		if len(dnsConfig.Nameservers) == 0 {
			fmt.Println("  (none were provided)")
		}
		for _, r := range dnsConfig.Nameservers {
			fmt.Printf("  - %v\n", r)
		}
		fmt.Print("\n")
		fmt.Println("Certificate Domains:")
		if len(dnsConfig.CertDomains) == 0 {
			fmt.Println("  (no certificate domains are configured)")
		}
		for _, r := range dnsConfig.CertDomains {
			fmt.Printf("  - %v\n", r)
		}
		fmt.Print("\n")
		fmt.Println("Additional DNS Records:")
		if len(dnsConfig.ExtraRecords) == 0 {
			fmt.Println("  (no extra records are configured)")
		}
		for _, er := range dnsConfig.ExtraRecords {
			if er.Type == "" {
				fmt.Printf("  - %-50s -> %v\n", er.Name, er.Value)
			} else {
				fmt.Printf("  - [%s] %-50s -> %v\n", er.Type, er.Name, er.Value)
			}
		}
		fmt.Print("\n")
		fmt.Println("Filtered suffixes when forwarding DNS queries as an exit node:")
		if len(dnsConfig.ExitNodeFilteredSet) == 0 {
			fmt.Println("  (no suffixes are filtered)")
		}
		for _, s := range dnsConfig.ExitNodeFilteredSet {
			fmt.Printf("  - %s\n", s)
		}
		fmt.Print("\n")
	}

	fmt.Println("=== System DNS configuration ===")
	fmt.Print("\n")
	fmt.Println("This is the DNS configuration that Tailscale believes your operating system is using.\nTailscale may use this configuration if 'Override Local DNS' is disabled in the admin console,\nor if no resolvers are provided by the coordination server.")
	fmt.Print("\n")
	osCfg, err := localClient.GetDNSOSConfig(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "not supported") {
			// avoids showing the HTTP error code which would be odd here
			fmt.Println("  (reading the system DNS configuration is not supported on this platform)")
		} else {
			fmt.Printf("  (failed to read system DNS configuration: %v)\n", err)
		}
	} else if osCfg == nil {
		fmt.Println("  (no OS DNS configuration available)")
	} else {
		fmt.Println("Nameservers:")
		if len(osCfg.Nameservers) == 0 {
			fmt.Println("  (no nameservers found, DNS queries might fail\nunless the coordination server is providing a nameserver)")
		}
		for _, ns := range osCfg.Nameservers {
			fmt.Printf("  - %v\n", ns)
		}
		fmt.Print("\n")
		fmt.Println("Search domains:")
		if len(osCfg.SearchDomains) == 0 {
			fmt.Println("  (no search domains found)")
		}
		for _, sd := range osCfg.SearchDomains {
			fmt.Printf("  - %v\n", sd)
		}
		if all {
			fmt.Print("\n")
			fmt.Println("Match domains:")
			if len(osCfg.MatchDomains) == 0 {
				fmt.Println("  (no match domains found)")
			}
			for _, md := range osCfg.MatchDomains {
				fmt.Printf("  - %v\n", md)
			}
		}
	}
	fmt.Print("\n")
	fmt.Println("[this is a preliminary version of this command; the output format may change in the future]")
	return nil
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

func dnsStatusLongHelp() string {
	return `The 'tailscale dns status' subcommand prints the current DNS status and configuration, including:
	
- Whether the built-in DNS forwarder is enabled.
- The MagicDNS configuration provided by the coordination server.
- Details on which resolver(s) Tailscale believes the system is using by default.

The --all flag can be used to output advanced debugging information, including fallback resolvers, nameservers, certificate domains, extra records, and the exit node filtered set.

=== Contents of the MagicDNS configuration ===

The MagicDNS configuration is provided by the coordination server to the client and includes the following components:

- MagicDNS enablement status: Indicates whether MagicDNS is enabled across the entire tailnet.

- MagicDNS Suffix: The DNS suffix used for devices within your tailnet.

- DNS Name: The DNS name that other devices in the tailnet can use to reach this device.

- Resolvers: The preferred DNS resolver(s) to be used for resolving queries, in order of preference. If no resolvers are listed here, the system defaults are used.

- Split DNS Routes: Custom DNS resolvers may be used to resolve hostnames in specific domains, this is also known as a 'Split DNS' configuration. The mapping of domains to their respective resolvers is provided here.

- Certificate Domains: The DNS names for which the coordination server will assist in provisioning TLS certificates.

- Extra Records: Additional DNS records that the coordination server might provide to the internal DNS resolver.

- Exit Node Filtered Set: DNS suffixes that the node, when acting as an exit node DNS proxy, will not answer.

For more information about the DNS functionality built into Tailscale, refer to https://tailscale.com/kb/1054/dns.`
}

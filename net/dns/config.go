// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:generate go run tailscale.com/cmd/viewer --type=Config --clonefunc

// Package dns contains code to configure and manage DNS settings.
package dns

import (
	"bufio"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sort"

	"tailscale.com/control/controlknobs"
	"tailscale.com/envknob"
	"tailscale.com/net/dns/publicdns"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/set"
)

// Config is a DNS configuration.
type Config struct {
	// AcceptDNS true if [Prefs.CorpDNS] is enabled (or --accept-dns=true).
	// This should be used for error handling and health reporting
	// purposes only.
	AcceptDNS bool
	// DefaultResolvers are the DNS resolvers to use for DNS names
	// which aren't covered by more specific per-domain routes below.
	// If empty, the OS's default resolvers (the ones that predate
	// Tailscale altering the configuration) are used.
	DefaultResolvers []*dnstype.Resolver
	// Routes maps a DNS suffix to the resolvers that should be used
	// for queries that fall within that suffix.
	// If a query doesn't match any entry in Routes, the
	// DefaultResolvers are used.
	// A Routes entry with no resolvers means the route should be
	// authoritatively answered using the contents of Hosts.
	Routes map[dnsname.FQDN][]*dnstype.Resolver
	// SearchDomains are DNS suffixes to try when expanding
	// single-label queries.
	SearchDomains []dnsname.FQDN
	// Hosts maps DNS FQDNs to their IPs, which can be a mix of IPv4
	// and IPv6.
	// Queries matching entries in Hosts are resolved locally by
	// 100.100.100.100 without leaving the machine.
	// Adding an entry to Hosts merely creates the record. If you want
	// it to resolve, you also need to add appropriate routes to
	// Routes.
	Hosts map[dnsname.FQDN][]netip.Addr
	// SubdomainHosts is a set of FQDNs from Hosts that should also
	// resolve subdomain queries to the same IPs. For example, if
	// "node.tailnet.ts.net" is in SubdomainHosts, then queries for
	// "anything.node.tailnet.ts.net" will resolve to node's IPs.
	SubdomainHosts set.Set[dnsname.FQDN]
	// OnlyIPv6, if true, uses the IPv6 service IP (for MagicDNS)
	// instead of the IPv4 version (100.100.100.100).
	OnlyIPv6 bool
}

var magicDNSDualStack = envknob.RegisterBool("TS_DEBUG_MAGIC_DNS_DUAL_STACK")

// serviceIPs returns the list of service IPs where MagicDNS is reachable.
//
// The provided knobs may be nil.
func (c *Config) serviceIPs(knobs *controlknobs.Knobs) []netip.Addr {
	if c.OnlyIPv6 {
		return []netip.Addr{tsaddr.TailscaleServiceIPv6()}
	}

	// See https://github.com/tailscale/tailscale/issues/15404 for the background
	// on the opt-in debug knob and the controlknob opt-out.
	if magicDNSDualStack() || !knobs.ShouldForceRegisterMagicDNSIPv4Only() {
		return []netip.Addr{
			tsaddr.TailscaleServiceIP(),
			tsaddr.TailscaleServiceIPv6(),
		}
	}

	return []netip.Addr{tsaddr.TailscaleServiceIP()}
}

// WriteToBufioWriter write a debug version of c for logs to w, omitting
// spammy stuff like *.arpa entries and replacing it with a total count.
func (c *Config) WriteToBufioWriter(w *bufio.Writer) {
	w.WriteString("{DefaultResolvers:")
	resolver.WriteDNSResolvers(w, c.DefaultResolvers)

	w.WriteString(" Routes:")
	resolver.WriteRoutes(w, c.Routes)

	fmt.Fprintf(w, " SearchDomains:%v", c.SearchDomains)
	fmt.Fprintf(w, " Hosts:%v", len(c.Hosts))
	w.WriteString("}")
}

// needsAnyResolvers reports whether c requires a resolver to be set
// at the OS level.
func (c Config) needsOSResolver() bool {
	return c.hasDefaultResolvers() || c.hasRoutes()
}

func (c Config) hasRoutes() bool {
	return len(c.Routes) > 0
}

// hasDefaultIPResolversOnly reports whether the only resolvers in c are
// DefaultResolvers, and that those resolvers are simple IP addresses
// that speak regular port 53 DNS.
func (c Config) hasDefaultIPResolversOnly() bool {
	if !c.hasDefaultResolvers() || c.hasRoutes() {
		return false
	}
	for _, r := range c.DefaultResolvers {
		if ipp, ok := r.IPPort(); !ok || ipp.Port() != 53 || publicdns.IPIsDoHOnlyServer(ipp.Addr()) {
			return false
		}
	}
	return true
}

// hasHostsWithoutSplitDNSRoutes reports whether c contains any Host entries
// that aren't covered by a SplitDNS route suffix.
func (c Config) hasHostsWithoutSplitDNSRoutes() bool {
	// TODO(bradfitz): this could be more efficient, but we imagine
	// the number of SplitDNS routes and/or hosts will be small.
	for host := range c.Hosts {
		if !c.hasSplitDNSRouteForHost(host) {
			return true
		}
	}
	return false
}

// hasSplitDNSRouteForHost reports whether c contains a SplitDNS route
// that contains hosts.
func (c Config) hasSplitDNSRouteForHost(host dnsname.FQDN) bool {
	for route := range c.Routes {
		if route.Contains(host) {
			return true
		}
	}
	return false
}

func (c Config) hasDefaultResolvers() bool {
	return len(c.DefaultResolvers) > 0
}

// singleResolverSet returns the resolvers used by c.Routes if all
// routes use the same resolvers, or nil if multiple sets of resolvers
// are specified.
func (c Config) singleResolverSet() []*dnstype.Resolver {
	var (
		prev            []*dnstype.Resolver
		prevInitialized bool
	)
	for _, resolvers := range c.Routes {
		if !prevInitialized {
			prev = resolvers
			prevInitialized = true
			continue
		}
		if !sameResolverNames(prev, resolvers) {
			return nil
		}
	}
	return prev
}

// matchDomains returns the list of match suffixes needed by Routes.
func (c Config) matchDomains() []dnsname.FQDN {
	ret := make([]dnsname.FQDN, 0, len(c.Routes))
	for suffix := range c.Routes {
		ret = append(ret, suffix)
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i].WithTrailingDot() < ret[j].WithTrailingDot()
	})
	return ret
}

func sameResolverNames(a, b []*dnstype.Resolver) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Addr != b[i].Addr {
			return false
		}
		if !slices.Equal(a[i].BootstrapResolution, b[i].BootstrapResolution) {
			return false
		}
	}
	return true
}

func (c *Config) Equal(o *Config) bool {
	if c == nil || o == nil {
		return c == o
	}
	return reflect.DeepEqual(c, o)
}

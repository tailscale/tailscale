// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"context"
	"net/netip"
	"sync"

	dnsmessage "golang.org/x/net/dns/dnsmessage"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
)

// LookupIP resolves host using the tailnet's DNS configuration: MagicDNS,
// ExtraRecords, search domains, split DNS routes, and global resolvers
// ("override local DNS" or an exit node's DNS proxy). Names with no
// configured upstream or local answer fall back to the host resolver.
// The host's hosts file is consulted only as part of that fallback.
//
// Use network "ip", "ip4", or "ip6". The "ip" network returns both address
// families, IPv4 first. IP literals are returned without DNS queries.
//
// Single-label names try the tailnet search domains before the bare name.
// Dotted names are tried as absolute names before appending search domains.
// A trailing dot disables search expansion. Short peer names resolve through
// the MagicDNS search domain when MagicDNS is enabled.
//
// LookupIP starts the server if needed and waits for the backend to run,
// as in [Server.Dial]. It is safe for concurrent use. Each lookup uses the
// current DNS configuration.
func (s *Server) LookupIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err := s.Start(); err != nil {
		return nil, err
	}
	if err := s.awaitRunning(ctx); err != nil {
		return nil, err
	}
	return s.dnsResolver().lookupIP(ctx, network, host)
}

func (s *Server) dnsResolver() *dnsResolver {
	return s.dnsRes.Get(func() *dnsResolver {
		var (
			mu         sync.Mutex
			searchMap  *netmap.NetworkMap
			searchList []dnsname.FQDN
		)
		return &dnsResolver{
			// Queries use [LocalBackend.QueryDNS] with the "tcp" family,
			// so truncated responses are retried over TCP.
			queryDNS: func(ctx context.Context, name dnsname.FQDN, qtype dnsmessage.Type) ([]byte, bool, error) {
				bs, _, err := s.lb.QueryDNS(ctx, name.WithoutTrailingDot(), qtype)
				return bs, s.hasConfiguredDNSRoute(name), err
			},
			searchDomains: func() []dnsname.FQDN {
				nm := s.lb.NetMap()
				mu.Lock()
				defer mu.Unlock()
				// Netmaps are replaced, not mutated.
				if nm != searchMap {
					searchList = searchDomainsFromNetmap(nm)
					searchMap = nm
				}
				return searchList
			},
		}
	})
}

// hasConfiguredDNSRoute reports whether the tailnet's DNS configuration
// routes name to an upstream resolver: a split DNS route covers name, or
// global resolvers are configured. Ambient cloud-host fallback resolvers
// are excluded. If the DNS feature is not in this build, or the backend
// is not started, hasConfiguredDNSRoute returns false.
func (s *Server) hasConfiguredDNSRoute(name dnsname.FQDN) bool {
	if !buildfeatures.HasDNS {
		return false
	}
	dm, ok := s.sys.DNSManager.GetOK()
	if !ok || dm == nil {
		return false
	}
	return dm.Resolver().HasConfiguredRouteFor(name)
}

// userDialResolve applies tailnet DNS policy to [Server.Dial].
func (s *Server) userDialResolve(ctx context.Context, network, host string, port uint16) ([]netip.AddrPort, error) {
	ips, err := s.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.AddrPort, 0, len(ips))
	for _, ip := range ips {
		out = append(out, netip.AddrPortFrom(ip, port))
	}
	return out, nil
}

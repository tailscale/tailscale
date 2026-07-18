// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package appchealth holds the health warning shared by the app connector
// features (classic app connectors in feature/appconnectors and the
// experimental connector in feature/conn25).
//
// It reports when a node acting as an app connector advertises DNS domains
// that it has no upstream nameserver to resolve, which makes those lookups
// silently fail with SERVFAIL. This surfaces the misconfiguration on the
// connector itself, rather than three hops away as a client-side SERVFAIL.
// See tailscale/tailscale#20516.
package appchealth

import (
	"tailscale.com/health"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

// Warnable warns that this node is an app connector advertising domains it has
// no nameserver to resolve.
var Warnable = health.Register(&health.Warnable{
	Code:      "app-connector-no-upstream-dns",
	Title:     "App connector can't resolve its domains",
	Severity:  health.SeverityMedium,
	DependsOn: []*health.Warnable{health.NetworkStatusWarnable},
	Text: health.StaticMessage("This app connector has no nameserver for the domains it serves, " +
		"so lookups will fail. Add a nameserver in the admin console, or set --accept-dns=false on this node."),
})

// State is the caller-owned edge-trigger state for Update. Each connector
// feature keeps one and passes a pointer to it, so the "no upstream resolver"
// log line fires only on the healthy->unhealthy transition rather than on
// every reconfig. It is not safe for concurrent use; callers already serialize
// their reconfig/health updates.
type State struct {
	unhealthy bool
}

// Update sets or clears [Warnable] on ht based on whether every domain the node
// advertises as an app connector has an upstream resolver.
//
// acceptDNS is whether the node has accept-DNS on: with it off, tailscaled
// leaves the OS resolver in place and forwards through it rather than through
// the config hasUpstream inspects, so we can't judge resolvability and don't
// warn. domains is the set of advertised domains. hasUpstream reports whether a
// query for the given name would reach some upstream resolver (typically backed
// by the DNS resolver's GetUpstreamResolvers).
//
// The first time Update transitions to unhealthy it logs the uncovered domains
// via logf as a durable, grep-able breadcrumb.
func Update(ht *health.Tracker, st *State, logf logger.Logf, acceptDNS bool, domains []string, hasUpstream func(dnsname.FQDN) bool) {
	setHealthy := func() {
		ht.SetHealthy(Warnable)
		st.unhealthy = false
	}

	if len(domains) == 0 {
		setHealthy()
		return
	}
	// With accept-DNS off we can't judge resolvability (the OS resolver is used
	// instead), so don't risk a false positive.
	if !acceptDNS {
		setHealthy()
		return
	}

	var uncovered []string
	for _, d := range domains {
		fqdn, err := dnsname.ToFQDN(d)
		if err != nil {
			continue
		}
		if !hasUpstream(fqdn) {
			uncovered = append(uncovered, d)
		}
	}
	if len(uncovered) == 0 {
		setHealthy()
		return
	}
	// Log the specific domains, edge-triggered on the healthy->unhealthy
	// transition so a steadily-misconfigured connector doesn't spew this on
	// every reconfig.
	if !st.unhealthy {
		logf("no upstream DNS resolver for advertised domains %v; lookups will SERVFAIL. Set a global nameserver in the admin console or --accept-dns=false on this node.", uncovered)
	}
	ht.SetUnhealthy(Warnable, nil)
	st.unhealthy = true
}

// SetHealthy clears [Warnable] and resets st. Connector features call this when
// they stop acting as a connector or the node goes down.
func SetHealthy(ht *health.Tracker, st *State) {
	ht.SetHealthy(Warnable)
	st.unhealthy = false
}

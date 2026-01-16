// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ingressservices contains shared types for exposing Kubernetes Services to tailnet.
// These are split into a separate package for consumption of
// non-Kubernetes shared libraries and binaries. Be mindful of not increasing
// dependency size for those consumers when adding anything new here.
package ingressservices

import (
	"net/netip"
	"time"
)

// IngressConfigKey is the key at which both the desired ingress firewall
// configuration is stored in the ingress proxies' ConfigMap and at which the
// recorded firewall configuration status is stored in the proxies' state
// Secrets.
const IngressConfigKey = "ingress-config.json"

// DNSRefreshInterval is how often to re-resolve DNS for ExternalName services.
// This matches the default check period used for TS_EXPERIMENTAL_DEST_DNS_NAME.
const DNSRefreshInterval = 10 * time.Minute

// Configs contains the desired configuration for ingress proxies firewall.  Map
// keys are Tailscale Service names.
type Configs map[string]Config

// GetConfig returns the desired configuration for the given Tailscale Service name.
func (cfgs *Configs) GetConfig(name string) *Config {
	if cfgs == nil {
		return nil
	}
	if cfg, ok := (*cfgs)[name]; ok {
		return &cfg
	}
	return nil
}

// Status contains the recorded firewall configuration status for a specific
// ingress proxy Pod.
// Pod IPs are used to identify the ingress proxy Pod.
type Status struct {
	Configs Configs `json:"configs,omitempty"`
	PodIPv4 string  `json:"podIPv4,omitempty"`
	PodIPv6 string  `json:"podIPv6,omitempty"`
}

// Config is an ingress service configuration.
// For ClusterIP-based services, IPv4Mapping and/or IPv6Mapping are set.
// For ExternalName services, ExternalName is set along with the TailscaleServiceIPs.
type Config struct {
	IPv4Mapping *Mapping `json:"IPv4Mapping,omitempty"`
	IPv6Mapping *Mapping `json:"IPv6Mapping,omitempty"`
	// ExternalName is the DNS name to forward traffic to for ExternalName services.
	// When set, IPv4Mapping and IPv6Mapping ClusterIP fields are ignored and
	// the DNS name is resolved at runtime to determine the destination IP.
	ExternalName string `json:"ExternalName,omitempty"`
	// TailscaleServiceIPv4 is the IPv4 VIP service address for ExternalName services.
	TailscaleServiceIPv4 netip.Addr `json:"TailscaleServiceIPv4,omitempty"`
	// TailscaleServiceIPv6 is the IPv6 VIP service address for ExternalName services.
	TailscaleServiceIPv6 netip.Addr `json:"TailscaleServiceIPv6,omitempty"`
	// ResolvedIPs stores the IP addresses that were resolved from ExternalName
	// when the DNAT rules were created. This is used to delete the correct rules
	// even if DNS has changed since creation.
	ResolvedIPs []netip.Addr `json:"ResolvedIPs,omitempty"`
	// LastDNSRefresh is the Unix timestamp (seconds) when ResolvedIPs was last
	// updated via DNS lookup. Used to determine when to re-resolve DNS for
	// ExternalName services.
	LastDNSRefresh int64 `json:"LastDNSRefresh,omitempty"`
	// DNSTTL is the TTL (in seconds) from the DNS response. Used to determine
	// when to re-resolve DNS. If zero, DNSRefreshInterval is used as fallback.
	DNSTTL uint32 `json:"DNSTTL,omitempty"`
}

// IsExternalName returns true if this config is for an ExternalName service.
func (c *Config) IsExternalName() bool {
	return c.ExternalName != ""
}

// EqualIgnoringResolved compares two configs for change detection, ignoring
// ResolvedIPs which are populated at runtime by containerboot. This is used
// to determine if the operator-provided config has changed without triggering
// unnecessary rule updates due to runtime-only fields.
func (c *Config) EqualIgnoringResolved(other *Config) bool {
	if c == nil || other == nil {
		return c == other
	}
	if c.IsExternalName() {
		return c.ExternalName == other.ExternalName &&
			c.TailscaleServiceIPv4 == other.TailscaleServiceIPv4 &&
			c.TailscaleServiceIPv6 == other.TailscaleServiceIPv6
	}
	// For non-ExternalName configs, compare all fields
	if c.IPv4Mapping == nil && other.IPv4Mapping != nil {
		return false
	}
	if c.IPv4Mapping != nil && other.IPv4Mapping == nil {
		return false
	}
	if c.IPv4Mapping != nil && *c.IPv4Mapping != *other.IPv4Mapping {
		return false
	}
	if c.IPv6Mapping == nil && other.IPv6Mapping != nil {
		return false
	}
	if c.IPv6Mapping != nil && other.IPv6Mapping == nil {
		return false
	}
	if c.IPv6Mapping != nil && *c.IPv6Mapping != *other.IPv6Mapping {
		return false
	}
	return true
}

// DNSRefreshNeeded returns true if this ExternalName config needs DNS re-resolution.
// Returns false for non-ExternalName configs. Uses the DNS TTL if available,
// capped at DNSRefreshInterval.
func (c *Config) DNSRefreshNeeded(now time.Time) bool {
	if c == nil || !c.IsExternalName() {
		return false
	}
	if c.LastDNSRefresh == 0 {
		return true
	}
	interval := DNSRefreshInterval
	if c.DNSTTL > 0 {
		ttl := time.Duration(c.DNSTTL) * time.Second
		if ttl < interval {
			interval = ttl
		}
	}
	lastRefresh := time.Unix(c.LastDNSRefresh, 0)
	return now.Sub(lastRefresh) >= interval
}

// Mapping describes a rule that forwards traffic from Tailscale Service IP to a
// Kubernetes Service IP.
type Mapping struct {
	TailscaleServiceIP netip.Addr `json:"TailscaleServiceIP"`
	ClusterIP          netip.Addr `json:"ClusterIP"`
}

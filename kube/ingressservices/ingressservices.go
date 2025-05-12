// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ingressservices contains shared types for exposing Kubernetes Services to tailnet.
// These are split into a separate package for consumption of
// non-Kubernetes shared libraries and binaries. Be mindful of not increasing
// dependency size for those consumers when adding anything new here.
package ingressservices

import "net/netip"

// IngressConfigKey is the key at which both the desired ingress firewall
// configuration is stored in the ingress proxies' ConfigMap and at which the
// recorded firewall configuration status is stored in the proxies' state
// Secrets.
const IngressConfigKey = "ingress-config.json"

// Configs contains the desired configuration for ingress proxies firewall.  Map
// keys are VIPService names.
type Configs map[string]Config

// GetConfig returns the desired configuration for the given VIPService name.
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
type Config struct {
	IPv4Mapping *Mapping `json:"IPv4Mapping,omitempty"`
	IPv6Mapping *Mapping `json:"IPv6Mapping,omitempty"`
}

// Mapping describes a rule that forwads traffic from VIPService IP to a
// Kubernetes Service IP.
type Mapping struct {
	VIPServiceIP netip.Addr `json:"VIPServiceIP"`
	ClusterIP    netip.Addr `json:"ClusterIP"`
}

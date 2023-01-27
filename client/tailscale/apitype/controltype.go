// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package apitype

type DNSConfig struct {
	Resolvers         []DNSResolver            `json:"resolvers"`
	FallbackResolvers []DNSResolver            `json:"fallbackResolvers"`
	Routes            map[string][]DNSResolver `json:"routes"`
	Domains           []string                 `json:"domains"`
	Nameservers       []string                 `json:"nameservers"`
	Proxied           bool                     `json:"proxied"`
}

type DNSResolver struct {
	Addr                string   `json:"addr"`
	BootstrapResolution []string `json:"bootstrapResolution,omitempty"`
}

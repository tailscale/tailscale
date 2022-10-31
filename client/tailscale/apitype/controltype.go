// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

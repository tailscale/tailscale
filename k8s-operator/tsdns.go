// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package kube

// TSHosts is a mapping of MagicDNS names to a list IPv4 or IPv6 addresses.
type TSHosts struct {
	Hosts map[string][]string `json:"hosts"`
}

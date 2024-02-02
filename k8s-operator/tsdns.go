// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package kube

const (
	Alpha1Version = "v1alpha1"

	DNSRecordsCMName = "dnsrecords"
	DNSRecordsCMKey  = "records.json"
)

type Records struct {
	// Version is the version of this Records configuration. Version is
	// written by the operator, i.e when it first populates the Records.
	// k8s-nameserver must verify that it knows how to parse a given
	// version.
	Version string `json:"version"`
	// IP4 contains a mapping of DNS names to IPv4 address(es).
	IP4 map[string][]string `json:"ip4"`
}

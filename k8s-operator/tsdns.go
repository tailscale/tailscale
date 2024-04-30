// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package kube

const Alpha1Version = "v1alpha1"

type Records struct {
	// Version is the version of this Records configuration. Version is
	// intended to be used by ./cmd/k8s-nameserver to determine whether it
	// can read this records configuration.
	Version string `json:"version"`
	// IP4 contains a mapping of DNS names to IPv4 address(es).
	IP4 map[string][]string `json:"ip4"`
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		BadDeps: map[string]string{
			"testing":                            "do not use testing package in production code",
			"gvisor.dev/gvisor/pkg/buffer":       "https://github.com/tailscale/tailscale/issues/9756",
			"gvisor.dev/gvisor/pkg/cpuid":        "https://github.com/tailscale/tailscale/issues/9756",
			"gvisor.dev/gvisor/pkg/tcpip":        "https://github.com/tailscale/tailscale/issues/9756",
			"gvisor.dev/gvisor/pkg/tcpip/header": "https://github.com/tailscale/tailscale/issues/9756",
			"tailscale.com/wgengine/filter":      "brings in bart, etc",
			"github.com/bits-and-blooms/bitset":  "unneeded in CLI",
			"tailscale.com/net/ipset":            "unneeded in CLI",
		},
	}.Check(t)
}

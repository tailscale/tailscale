// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

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
		},
	}.Check(t)
}

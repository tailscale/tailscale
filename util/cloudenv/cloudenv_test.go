// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cloudenv

import (
	"flag"
	"net/netip"
	"testing"
)

var extNetwork = flag.Bool("use-external-network", false, "use the external network in tests")

// Informational only since we can run tests in a variety of places.
func TestGetCloud(t *testing.T) {
	if !*extNetwork {
		t.Skip("skipping test without --use-external-network")
	}

	cloud := getCloud()
	t.Logf("Cloud: %q", cloud)
	t.Logf("Cloud.HasInternalTLD: %v", cloud.HasInternalTLD())
	t.Logf("Cloud.ResolverIP: %q", cloud.ResolverIP())
}

func TestGetDigitalOceanResolver(t *testing.T) {
	addr := netip.MustParseAddr(getDigitalOceanResolver())
	t.Logf("got: %v", addr)
}

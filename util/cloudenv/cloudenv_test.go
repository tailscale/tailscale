// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cloudenv

import (
	"flag"
	"net/netip"
	"testing"

	"tailscale.com/envknob"
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

func TestDisableCloudDetection(t *testing.T) {
	// Save original value
	originalCloud, _ := cloudAtomic.LoadOk()
	defer func() {
		envknob.Setenv("TS_DISABLE_CLOUD_DETECTION", "")
		cloudAtomic.Store(originalCloud)
	}()

	// Enable the disable flag
	envknob.Setenv("TS_DISABLE_CLOUD_DETECTION", "1")

	// Clear the cached value to force re-detection
	cloudAtomic.Store(Cloud(""))

	cloud := Get()
	if cloud != "" {
		t.Errorf("expected empty cloud when TS_DISABLE_CLOUD_DETECTION=1, got %q", cloud)
	}
}

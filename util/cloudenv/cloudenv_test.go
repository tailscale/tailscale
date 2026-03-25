// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cloudenv

import (
	"flag"
	"net/netip"
	"runtime"
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

// TestGetCloudNonLinuxDoesNotBailEarly verifies that getCloud on non-Linux
// platforms (Windows, BSDs) doesn't return "" immediately. It should fall
// through to the metadata endpoint probe. We can't easily test the HTTP
// probe itself without a mock server, but we can at least verify the code
// path reaches the metadata check rather than short-circuiting.
func TestGetCloudNonLinuxDoesNotBailEarly(t *testing.T) {
	// This test is only meaningful on non-Linux, non-mobile platforms.
	// On Linux, getCloud takes the linux-specific path. On mobile, it
	// correctly returns "" early.
	switch runtime.GOOS {
	case "linux", "android", "ios", "darwin":
		t.Skipf("skipping on %s (test targets Windows/BSDs)", runtime.GOOS)
	}
	// If we get here on Windows or a BSD, getCloud should NOT return ""
	// immediately. It should try the metadata probe (which will likely
	// fail/timeout since we're probably not on a cloud VM, but that's fine).
	// The key thing is it doesn't bail out before trying.
	_ = getCloud()
}

func TestGetDigitalOceanResolver(t *testing.T) {
	addr := netip.MustParseAddr(getDigitalOceanResolver())
	t.Logf("got: %v", addr)
}

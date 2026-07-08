// Copyright (c) Tailscale Inc & contributors
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

func TestCloudFromSMBIOS(t *testing.T) {
	tests := []struct {
		name         string
		biosVendor   string
		sysVendor    string
		productName  string
		wantCloud    Cloud
		wantMetadata bool
	}{
		{name: "empty"},
		{name: "aws", biosVendor: "Amazon EC2", wantCloud: AWS},
		{name: "aws-suffix", biosVendor: "1.0-1.amazon", wantCloud: AWS},
		{name: "digitalocean", sysVendor: "DigitalOcean", wantCloud: DigitalOcean},
		{name: "hetzner", sysVendor: "Hetzner", wantCloud: Hetzner},
		{name: "gcp", productName: "Google Compute Engine", wantCloud: GCP},
		{name: "gcp-old", productName: "Google", wantMetadata: true},
		{name: "azure-product", productName: "Virtual Machine", wantMetadata: true},
		{name: "azure-bios", biosVendor: "Microsoft Corporation", wantMetadata: true},
		{name: "unknown", biosVendor: "SeaBIOS", sysVendor: "QEMU", productName: "Standard PC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCloud, gotMetadata := cloudFromSMBIOS(tt.biosVendor, tt.sysVendor, tt.productName)
			if gotCloud != tt.wantCloud || gotMetadata != tt.wantMetadata {
				t.Errorf("cloudFromSMBIOS(%q, %q, %q) = (%q, %v); want (%q, %v)",
					tt.biosVendor, tt.sysVendor, tt.productName,
					gotCloud, gotMetadata, tt.wantCloud, tt.wantMetadata)
			}
		})
	}
}

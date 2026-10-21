// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cloudenv

import (
	"flag"
	"net/netip"
	"slices"
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
		name        string
		biosVendor  string
		sysVendor   string
		productName string
		wantCloud   Cloud
		wantProbe   bool
		wantReads   []string // identifiers read, in order
	}{
		{name: "empty", wantReads: []string{"bios_vendor", "sys_vendor", "product_name"}},
		{name: "aws", biosVendor: "Amazon EC2", wantCloud: AWS,
			wantReads: []string{"bios_vendor"}},
		{name: "aws-suffix", biosVendor: "1.0-1.amazon", wantCloud: AWS,
			wantReads: []string{"bios_vendor"}},
		{name: "digitalocean", sysVendor: "DigitalOcean", wantCloud: DigitalOcean,
			wantReads: []string{"bios_vendor", "sys_vendor"}},
		{name: "hetzner", sysVendor: "Hetzner", wantCloud: Hetzner,
			wantReads: []string{"bios_vendor", "sys_vendor"}},
		{name: "gcp", productName: "Google Compute Engine", wantCloud: GCP,
			wantReads: []string{"bios_vendor", "sys_vendor", "product_name"}},
		{name: "gcp-old", productName: "Google", wantProbe: true,
			wantReads: []string{"bios_vendor", "sys_vendor", "product_name"}},
		{name: "azure-product", productName: "Virtual Machine", wantProbe: true,
			wantReads: []string{"bios_vendor", "sys_vendor", "product_name"}},
		{name: "azure-bios", biosVendor: "Microsoft Corporation", wantProbe: true,
			wantReads: []string{"bios_vendor", "sys_vendor", "product_name"}},
		{name: "unknown", biosVendor: "SeaBIOS", sysVendor: "QEMU", productName: "Standard PC",
			wantReads: []string{"bios_vendor", "sys_vendor", "product_name"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reads []string
			gotCloud, gotProbe := cloudFromSMBIOS(func(dmiName string) string {
				reads = append(reads, dmiName)
				switch dmiName {
				case "bios_vendor":
					return tt.biosVendor
				case "sys_vendor":
					return tt.sysVendor
				case "product_name":
					return tt.productName
				}
				t.Errorf("read of unknown DMI identifier %q", dmiName)
				return ""
			})
			if gotCloud != tt.wantCloud || gotProbe != tt.wantProbe {
				t.Errorf("cloudFromSMBIOS(%q, %q, %q) = (%q, %v); want (%q, %v)",
					tt.biosVendor, tt.sysVendor, tt.productName,
					gotCloud, gotProbe, tt.wantCloud, tt.wantProbe)
			}
			if !slices.Equal(reads, tt.wantReads) {
				t.Errorf("read %q; want %q", reads, tt.wantReads)
			}
		})
	}
}

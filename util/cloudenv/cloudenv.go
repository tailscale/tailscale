// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cloudenv reports which known cloud environment we're running in.
package cloudenv

import (
	"os"
	"runtime"
	"strings"
	"sync/atomic"

	gcpmetadata "cloud.google.com/go/compute/metadata"
)

// GoogleMetadataAndDNSIP is the metadata IP used by Google Cloud.
// It's also the *.internal DNS server, and proxies to 8.8.8.8.
const GoogleMetadataAndDNSIP = "169.254.169.254"

// AWSResolverIP is the IP address of the AWS DNS server.
// See https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html
const AWSResolverIP = "169.254.169.253"

// Cloud is a recognize cloud environment with properties that
// Tailscale can specialize for in places.
type Cloud string

const (
	GCP = Cloud("gcp") // Google Cloud
	AWS = Cloud("aws") // Amazon Web Services (EC2 in particular)
)

// ResolverIP returns the cloud host's recursive DNS server or the
// empty string if not available.
func (c Cloud) ResolverIP() string {
	switch c {
	case GCP:
		return GoogleMetadataAndDNSIP
	case AWS:
		return AWSResolverIP
	}
	return ""
}

// HasInternalTLD reports whether c is a cloud environment
// whose ResolverIP serves *.internal records.
func (c Cloud) HasInternalTLD() bool {
	switch c {
	case GCP, AWS:
		return true
	}
	return false
}

var cloudAtomic atomic.Value // of Cloud

// Get returns the current cloud, or the empty string if unknown.
func Get() Cloud {
	c, ok := cloudAtomic.Load().(Cloud)
	if ok {
		return c
	}
	c = getCloud()
	cloudAtomic.Store(c) // even if empty
	return c
}

func getCloud() Cloud {
	// TODO(bradfitz): also detect AWS on Windows, etc. Just try to hit the metadata server
	// and see if it's there? But it might be turned off. Do some small-timeout DNS request
	// to 169.254.169.253 and see if it replies? But which DNS request?
	if runtime.GOOS == "linux" {
		biosVendorB, _ := os.ReadFile("/sys/class/dmi/id/bios_vendor")
		biosVendor := strings.TrimSpace(string(biosVendorB))
		if biosVendor == "Amazon EC2" || strings.HasSuffix(biosVendor, ".amazon") {
			return AWS
		}
	}
	if gcpmetadata.OnGCE() {
		return GCP
	}
	// TODO: more, as needed.
	return ""
}

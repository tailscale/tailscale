// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cloudenv reports which known cloud environment we're running in.
package cloudenv

import (
	"sync/atomic"

	gcpmetadata "cloud.google.com/go/compute/metadata"
)

// GoogleMetadataAndDNSIP is the metadata IP used by Google Cloud.
// It's also the *.internal DNS server, and proxies to 8.8.8.8.
const GoogleMetadataAndDNSIP = "169.254.169.254"

// Cloud is a recognize cloud environment with properties that
// Tailscale can specialize for in places.
type Cloud string

const (
	GCP = Cloud("gcp") // Google Cloud
)

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
	if gcpmetadata.OnGCE() {
		return GCP
	}
	// TODO: more, as needed.
	return ""
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package cloudenv reports which known cloud environment we're running in.
package cloudenv

import (
	"context"
	"encoding/json"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/syncs"
	"tailscale.com/types/lazy"
)

// CommonNonRoutableMetadataIP is the IP address of the metadata server
// on Amazon EC2, Google Compute Engine, and Azure. It's not routable.
// (169.254.0.0/16 is a Link Local range: RFC 3927)
const CommonNonRoutableMetadataIP = "169.254.169.254"

// GoogleMetadataAndDNSIP is the metadata IP used by Google Cloud.
// It's also the *.internal DNS server, and proxies to 8.8.8.8.
const GoogleMetadataAndDNSIP = "169.254.169.254"

// AWSResolverIP is the IP address of the AWS DNS server.
// See https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html
const AWSResolverIP = "169.254.169.253"

// AzureResolverIP is Azure's DNS resolver IP.
// See https://docs.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16
const AzureResolverIP = "168.63.129.16"

// Cloud is a recognize cloud environment with properties that
// Tailscale can specialize for in places.
type Cloud string

const (
	AWS          = Cloud("aws")          // Amazon Web Services (EC2 in particular)
	Azure        = Cloud("azure")        // Microsoft Azure
	GCP          = Cloud("gcp")          // Google Cloud
	DigitalOcean = Cloud("digitalocean") // DigitalOcean
)

// ResolverIP returns the cloud host's recursive DNS server or the
// empty string if not available.
func (c Cloud) ResolverIP() string {
	if !buildfeatures.HasCloud {
		return ""
	}
	switch c {
	case GCP:
		return GoogleMetadataAndDNSIP
	case AWS:
		return AWSResolverIP
	case Azure:
		return AzureResolverIP
	case DigitalOcean:
		return getDigitalOceanResolver()
	}
	return ""
}

var (
	// https://docs.digitalocean.com/support/check-your-droplets-network-configuration/
	digitalOceanResolvers = []string{"67.207.67.2", "67.207.67.3"}
	digitalOceanResolver  lazy.SyncValue[string]
)

func getDigitalOceanResolver() string {
	// Randomly select one of the available resolvers so we don't overload
	// one of them by sending all traffic there.
	return digitalOceanResolver.Get(func() string {
		return digitalOceanResolvers[rand.IntN(len(digitalOceanResolvers))]
	})
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

var cloudAtomic syncs.AtomicValue[Cloud]

// Get returns the current cloud, or the empty string if unknown.
func Get() Cloud {
	if !buildfeatures.HasCloud {
		return ""
	}
	if c, ok := cloudAtomic.LoadOk(); ok {
		return c
	}
	c := getCloud()
	cloudAtomic.Store(c) // even if empty
	return c
}

func readFileTrimmed(name string) string {
	v, _ := os.ReadFile(name)
	return strings.TrimSpace(string(v))
}

func getCloud() Cloud {
	var hitMetadata bool
	switch runtime.GOOS {
	case "android", "ios", "darwin":
		// Assume these aren't running on a cloud.
		return ""
	case "linux":
		biosVendor := readFileTrimmed("/sys/class/dmi/id/bios_vendor")
		if biosVendor == "Amazon EC2" || strings.HasSuffix(biosVendor, ".amazon") {
			return AWS
		}

		sysVendor := readFileTrimmed("/sys/class/dmi/id/sys_vendor")
		if sysVendor == "DigitalOcean" {
			return DigitalOcean
		}
		// TODO(andrew): "Vultr" is also valid if we need it

		prod := readFileTrimmed("/sys/class/dmi/id/product_name")
		if prod == "Google Compute Engine" {
			return GCP
		}
		if prod == "Google" { // old GCP VMs, it seems
			hitMetadata = true
		}
		if prod == "Virtual Machine" || biosVendor == "Microsoft Corporation" {
			// Azure, or maybe all Hyper-V?
			hitMetadata = true
		}

	default:
		// TODO(bradfitz): use Win32_SystemEnclosure from WMI or something on
		// Windows to see if it's a physical machine and skip the cloud check
		// early. Otherwise use similar clues as Linux about whether we should
		// burn up to 2 seconds waiting for a metadata server that might not be
		// there. And for BSDs, look where the /sys stuff is.
		return ""
	}
	if !hitMetadata {
		return ""
	}

	const maxWait = 2 * time.Second
	tr := &http.Transport{
		DisableKeepAlives: true,
		Dial: (&net.Dialer{
			Timeout: maxWait,
		}).Dial,
	}
	ctx, cancel := context.WithTimeout(context.Background(), maxWait)
	defer cancel()

	// We want to hit CommonNonRoutableMetadataIP to see if we're on AWS, GCP,
	// or Azure. All three (and many others) use the same metadata IP.
	//
	// But to avoid triggering the AWS CloudWatch "MetadataNoToken" metric (for which
	// there might be an alert registered?), make our initial request be a token
	// request. This only works on AWS, but the failing HTTP response on other clouds gives
	// us enough clues about which cloud we're on.
	req, err := http.NewRequestWithContext(ctx, "PUT", "http://"+CommonNonRoutableMetadataIP+"/latest/api/token", strings.NewReader(""))
	if err != nil {
		log.Printf("cloudenv: [unexpected] error creating request: %v", err)
		return ""
	}
	req.Header.Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "5")

	res, err := tr.RoundTrip(req)
	if err != nil {
		return ""
	}
	res.Body.Close()
	if res.Header.Get("Metadata-Flavor") == "Google" {
		return GCP
	}
	server := res.Header.Get("Server")
	if server == "EC2ws" {
		return AWS
	}
	if strings.HasPrefix(server, "Microsoft") {
		// e.g. "Microsoft-IIS/10.0"
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+CommonNonRoutableMetadataIP+"/metadata/instance/compute?api-version=2021-02-01", nil)
		req.Header.Set("Metadata", "true")
		res, err := tr.RoundTrip(req)
		if err != nil {
			return ""
		}
		defer res.Body.Close()
		var meta struct {
			AzEnvironment string `json:"azEnvironment"`
		}
		if err := json.NewDecoder(res.Body).Decode(&meta); err != nil {
			return ""
		}
		if strings.HasPrefix(meta.AzEnvironment, "Azure") {
			return Azure
		}
		return ""
	}

	// TODO: more, as needed.
	return ""
}

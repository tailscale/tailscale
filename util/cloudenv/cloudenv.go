// Copyright (c) Tailscale Inc & contributors
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
	Hetzner      = Cloud("hetzner")      // Hetzner Cloud
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
	case Hetzner:
		return getHetznerResolver()
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

var (
	// https://docs.hetzner.com/robot/dedicated-server/general-information/recursive-name-servers/
	// IPv6 resolvers also exist: 2a01:4ff:ff00::add:1, 2a01:4ff:ff00::add:2.
	hetznerResolvers = []string{"185.12.64.1", "185.12.64.2"}
	hetznerResolver  lazy.SyncValue[string]
)

func getHetznerResolver() string {
	// Randomly select one of the available resolvers so we don't overload
	// one of them by sending all traffic there.
	return hetznerResolver.Get(func() string {
		return hetznerResolvers[rand.IntN(len(hetznerResolvers))]
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

// cloudFromSMBIOS reports which cloud we're running in, based on the
// SMBIOS/DMI identifiers exposed by the hardware to the OS. It fetches each
// identifier by calling read with its DMI name ("bios_vendor", "sys_vendor",
// or "product_name"), reading only as many as needed to decide; read should
// return the empty string for identifiers that are unavailable.
//
// If c is empty and probeMetadata is true, the identifiers alone were
// inconclusive and the caller should probe the well-known metadata server to
// determine the cloud.
func cloudFromSMBIOS(read func(dmiName string) string) (c Cloud, probeMetadata bool) {
	biosVendor := read("bios_vendor")
	if biosVendor == "Amazon EC2" || strings.HasSuffix(biosVendor, ".amazon") {
		return AWS, false
	}
	switch read("sys_vendor") {
	case "DigitalOcean":
		return DigitalOcean, false
	case "Hetzner":
		return Hetzner, false
	}
	// TODO(andrew): "Vultr" is also valid if we need it
	switch read("product_name") {
	case "Google Compute Engine":
		return GCP, false
	case "Google":
		// Old GCP VMs, it seems.
		return "", true
	case "Virtual Machine":
		// Azure, or maybe all Hyper-V?
		return "", true
	}
	if biosVendor == "Microsoft Corporation" {
		// Azure, or maybe all Hyper-V?
		return "", true
	}
	return "", false
}

func getCloud() Cloud {
	var probeMetadata bool
	switch runtime.GOOS {
	case "android", "ios", "darwin":
		// Assume these aren't running on a cloud.
		return ""
	case "linux":
		var c Cloud
		c, probeMetadata = cloudFromSMBIOS(func(dmiName string) string {
			return readFileTrimmed("/sys/class/dmi/id/" + dmiName)
		})
		if c != "" {
			return c
		}

	default:
		// On other operating systems (notably Windows and the BSDs) we don't
		// yet have a cheap, OS-specific way to read the SMBIOS/DMI clues that
		// the Linux path above uses, so fall back to probing the metadata
		// server directly. The probe below is OS-independent and detects AWS,
		// GCP, and Azure. Get caches the result, so this cost is paid at most
		// once per process.
		//
		// TODO: read the SMBIOS clues on these platforms too (Win32_SystemEnclosure
		// from WMI on Windows, kenv/sysctl on the BSDs) and feed them to
		// cloudFromSMBIOS, so we can skip this probe on machines that clearly
		// aren't on a cloud.
		probeMetadata = true
	}
	if !probeMetadata {
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

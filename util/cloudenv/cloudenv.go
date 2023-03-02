// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package cloudenv reports which known cloud environment we're running in.
package cloudenv

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"tailscale.com/syncs"
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
	AWS   = Cloud("aws")   // Amazon Web Services (EC2 in particular)
	Azure = Cloud("azure") // Microsoft Azure
	GCP   = Cloud("gcp")   // Google Cloud
)

// ResolverIP returns the cloud host's recursive DNS server or the
// empty string if not available.
func (c Cloud) ResolverIP() string {
	switch c {
	case GCP:
		return GoogleMetadataAndDNSIP
	case AWS:
		return AWSResolverIP
	case Azure:
		return AzureResolverIP
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

var cloudAtomic syncs.AtomicValue[Cloud]

// Get returns the current cloud, or the empty string if unknown.
func Get() Cloud {
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

// ApproximateLocation returns the approximate geographic location of the
// region that the current cloud host is running in.
//
// If the current host is not running in the cloud, if cloud provider is not
// supported, or if the current region could not be determined, then (0, 0)
// will be returned.
func (c Cloud) ApproximateLocation() (lat, lon float64) {
	switch c {
	case AWS:
		loc := getApproximateLocationAWS()
		return loc.lat, loc.lon
	case GCP:
		// TODO
	case Azure:
		// TODO
	}
	return 0, 0
}

type location struct{ lat, lon float64 }

var noLocation location

var approximateAWSRegionLocation = map[string]location{
	"af-south-1":     {-33.928992, 18.417396},    // "CPT" / Cape Town, South Africa
	"ap-east-1":      {22.2793278, 114.1628131},  // "HKG" / Hong Kong
	"ap-northeast-1": {35.6812665, 139.757653},   // "NRT" / Tokyo, Japan
	"ap-northeast-2": {37.5666791, 126.9782914},  // "ICN" / Seoul, Korea
	"ap-northeast-3": {34.661629, 135.4999268},   // "KIX" / Osaka, Japan
	"ap-south-1":     {19.0785451, 72.878176},    // "BOM" / Mumbai, India
	"ap-south-2":     {17.38878595, 78.46106473}, // "HYD" / Hyderabad, India
	"ap-southeast-1": {1.357107, 103.8194992},    // "SIN" / Singapore
	"ap-southeast-2": {-33.8698439, 151.2082848}, // "SYD" / Sydney, Australia
	"ap-southeast-3": {-6.1753942, 106.827183},   // "CGK" / Jakarta, Indonesia
	"ap-southeast-4": {-37.8142176, 144.9631608}, // "MEL" / Melbourne, Australia
	"ca-central-1":   {45.5031824, -73.5698065},  // "YUL" / Montreal, Canada
	"cn-north-1":     {39.906217, 116.3912757},   // "BJS" / Beijing
	"cn-northwest-1": {37.4999947, 105.1928783},  // "ZHY" / Zhongwei
	"eu-central-1":   {50.1106444, 8.6820917},    // "FRA" / Frankfurt, Germany
	"eu-central-2":   {47.3744489, 8.5410422},    // "ZRH" / Zurich, Switzerland
	"eu-north-1":     {59.3251172, 18.0710935},   // "ARN" / Stockholm, Sweden
	"eu-south-1":     {45.4641943, 9.1896346},    // "MXP" / Milan, Italy
	"eu-south-2":     {41.6521342, -0.8809428},   // "ZAZ" / Zaragoza, Spain
	"eu-west-1":      {53.3498006, -6.2602964},   // "DUB" / Dublin, Ireland
	"eu-west-2":      {51.5073359, -0.12765},     // "LHR" / London, England
	"eu-west-3":      {48.8588897, 2.32004102},   // "CDG" / Paris, France
	"me-south-1":     {26.1551249, 50.5344606},   // "BAH" / Bahrain
	"sa-east-1":      {-23.5506507, -46.6333824}, // "GRU" / São Paulo, Brazil
	"us-east-1":      {38.8950368, -77.0365427},  // "IAD" / Washington D.C., USA
	"us-east-2":      {39.9622601, -83.0007065},  // "CMH" / Columbus, Ohio, USA
	"us-gov-east-1":  {39.9622601, -83.0007065},  // "CMH" / Columbus, Ohio, USA
	"us-gov-west-1":  {45.5202471, -122.674194},  // "PDX" / Portland, Oregon, USA
	"us-west-1":      {37.7790262, -122.419906},  // "SFO" / San Francisco, California, USA
	"us-west-2":      {45.5202471, -122.674194},  // "PDX" / Portland, Oregon, USA

	// NOTE: it's not public where in Dubai this is
	"me-central-1": {25.07428234, 55.18853865}, // Dubai
}

func getApproximateLocationAWS() location {
	const maxWait = 2 * time.Second
	tr := &http.Transport{
		DisableKeepAlives: true,
		Dial: (&net.Dialer{
			Timeout: maxWait,
		}).Dial,
	}
	ctx, cancel := context.WithTimeout(context.Background(), maxWait)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "PUT", "http://"+CommonNonRoutableMetadataIP+"/latest/api/token", nil)
	if err != nil {
		return noLocation
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "30")

	res, err := tr.RoundTrip(req)
	if err != nil {
		return noLocation
	}
	token, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return noLocation
	}

	req, err = http.NewRequestWithContext(ctx, "GET", "http://"+CommonNonRoutableMetadataIP+"/latest/dynamic/instance-identity/document", nil)
	if err != nil {
		return noLocation
	}
	req.Header.Set("X-aws-ec2-metadata-token", string(bytes.TrimSpace(token)))

	res, err = tr.RoundTrip(req)
	if err != nil {
		return noLocation
	}
	defer res.Body.Close()

	var identityDocument struct {
		Region string `json:"region"`
	}
	if err := json.NewDecoder(res.Body).Decode(&identityDocument); err != nil {
		return noLocation
	}

	return approximateAWSRegionLocation[identityDocument.Region]
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !(ios || android || js)

package magicsock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/types/logger"
	"tailscale.com/util/cloudenv"
)

const maxCloudInfoWait = 2 * time.Second

type cloudInfo struct {
	client http.Client
	logf   logger.Logf

	// The following parameters are fixed for the lifetime of the cloudInfo
	// object, but are used for testing.
	cloud    cloudenv.Cloud
	endpoint string
}

func newCloudInfo(logf logger.Logf) *cloudInfo {
	if !buildfeatures.HasCloud {
		return nil
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
		Dial: (&net.Dialer{
			Timeout: maxCloudInfoWait,
		}).Dial,
	}

	return &cloudInfo{
		client:   http.Client{Transport: tr},
		logf:     logf,
		cloud:    cloudenv.Get(),
		endpoint: "http://" + cloudenv.CommonNonRoutableMetadataIP,
	}
}

// GetPublicIPs returns any public IPs attached to the current cloud instance,
// if the tailscaled process is running in a known cloud and there are any such
// IPs present.
func (ci *cloudInfo) GetPublicIPs(ctx context.Context) ([]netip.Addr, error) {
	if !buildfeatures.HasCloud {
		return nil, nil
	}
	switch ci.cloud {
	case cloudenv.AWS:
		ret, err := ci.getAWS(ctx)
		ci.logf("[v1] cloudinfo.GetPublicIPs: AWS: %v, %v", ret, err)
		return ret, err
	}

	return nil, nil
}

// getAWSMetadata makes a request to the AWS metadata service at the given
// path, authenticating with the provided IMDSv2 token. The returned metadata
// is split by newline and returned as a slice.
func (ci *cloudInfo) getAWSMetadata(ctx context.Context, token, path string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", ci.endpoint+path, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request to %q: %w", path, err)
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)

	resp, err := ci.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request to metadata service %q: %w", path, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Good
	case http.StatusNotFound:
		// Nothing found, but this isn't an error; just return
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body for %q: %w", path, err)
	}

	return strings.Split(strings.TrimSpace(string(body)), "\n"), nil
}

// getAWS returns all public IPv4 and IPv6 addresses present in the AWS instance metadata.
func (ci *cloudInfo) getAWS(ctx context.Context) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, maxCloudInfoWait)
	defer cancel()

	// Get a token so we can query the metadata service.
	req, err := http.NewRequestWithContext(ctx, "PUT", ci.endpoint+"/latest/api/token", nil)
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "10")

	resp, err := ci.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making token request to metadata service: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("reading token response body: %w", err)
	}
	token := string(body)

	server := resp.Header.Get("Server")
	if server != "EC2ws" {
		return nil, fmt.Errorf("unexpected server header: %q", server)
	}

	// Iterate over all interfaces and get their public IP addresses, both IPv4 and IPv6.
	macAddrs, err := ci.getAWSMetadata(ctx, token, "/latest/meta-data/network/interfaces/macs/")
	if err != nil {
		return nil, fmt.Errorf("getting interface MAC addresses: %w", err)
	}

	var (
		addrs []netip.Addr
		errs  []error
	)

	addAddr := func(addr string) {
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("parsing IP address %q: %w", addr, err))
			return
		}
		addrs = append(addrs, ip)
	}
	for _, mac := range macAddrs {
		ips, err := ci.getAWSMetadata(ctx, token, "/latest/meta-data/network/interfaces/macs/"+mac+"/public-ipv4s")
		if err != nil {
			errs = append(errs, fmt.Errorf("getting IPv4 addresses for %q: %w", mac, err))
			continue
		}

		for _, ip := range ips {
			addAddr(ip)
		}

		// Try querying for IPv6 addresses.
		ips, err = ci.getAWSMetadata(ctx, token, "/latest/meta-data/network/interfaces/macs/"+mac+"/ipv6s")
		if err != nil {
			errs = append(errs, fmt.Errorf("getting IPv6 addresses for %q: %w", mac, err))
			continue
		}
		for _, ip := range ips {
			addAddr(ip)
		}
	}

	// Sort the returned addresses for determinism.
	slices.SortFunc(addrs, func(a, b netip.Addr) int {
		return a.Compare(b)
	})

	// Preferentially return any addresses we found, even if there were errors.
	if len(addrs) > 0 {
		return addrs, nil
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("getting IP addresses: %w", errors.Join(errs...))
	}
	return nil, nil
}

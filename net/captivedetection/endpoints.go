// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"cmp"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"

	"go4.org/mem"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// EndpointProvider is an enum that represents the source of an Endpoint.
type EndpointProvider int

const (
	// DERPMapPreferred is used for an endpoint that is a DERP node contained in the current preferred DERP region,
	// as provided by the DERPMap.
	DERPMapPreferred EndpointProvider = iota
	// DERPMapOther is used for an endpoint that is a DERP node, but not contained in the current preferred DERP region.
	DERPMapOther
	// Tailscale is used for endpoints that are the Tailscale coordination server or admin console.
	Tailscale
)

func (p EndpointProvider) String() string {
	switch p {
	case DERPMapPreferred:
		return "DERPMapPreferred"
	case Tailscale:
		return "Tailscale"
	case DERPMapOther:
		return "DERPMapOther"
	default:
		return fmt.Sprintf("EndpointProvider(%d)", p)
	}
}

// Endpoint represents a URL that can be used to detect a captive portal, along with the expected
// result of the HTTP request.
type Endpoint struct {
	// URL is the URL that we make an HTTP request to as part of the captive portal detection process.
	URL *url.URL
	// StatusCode is the expected HTTP status code that we expect to see in the response.
	StatusCode int
	// ExpectedContent is a string that we expect to see contained in the response body. If this is non-empty,
	// we will check that the response body contains this string. If it is empty, we will not check the response body
	// and only check the status code.
	ExpectedContent string
	// SupportsTailscaleChallenge is true if the endpoint will return the sent value of the X-Tailscale-Challenge
	// HTTP header in its HTTP response.
	SupportsTailscaleChallenge bool
	// Provider is the source of the endpoint. This is used to prioritize certain endpoints over others
	// (for example, a DERP node in the preferred region should always be used first).
	Provider EndpointProvider
}

func (e Endpoint) String() string {
	return fmt.Sprintf("Endpoint{URL=%q, StatusCode=%d, ExpectedContent=%q, SupportsTailscaleChallenge=%v, Provider=%s}", e.URL, e.StatusCode, e.ExpectedContent, e.SupportsTailscaleChallenge, e.Provider.String())
}

func (e Endpoint) Equal(other Endpoint) bool {
	return e.URL.String() == other.URL.String() &&
		e.StatusCode == other.StatusCode &&
		e.ExpectedContent == other.ExpectedContent &&
		e.SupportsTailscaleChallenge == other.SupportsTailscaleChallenge &&
		e.Provider == other.Provider
}

// availableEndpoints returns a set of Endpoints which can be used for captive portal detection by performing
// one or more HTTP requests and looking at the response. The returned Endpoints are ordered by preference,
// with the most preferred Endpoint being the first in the slice.
func availableEndpoints(derpMap *tailcfg.DERPMap, preferredDERPRegionID int, logf logger.Logf, goos string) []Endpoint {
	endpoints := []Endpoint{}

	if derpMap == nil || len(derpMap.Regions) == 0 {
		// When the client first starts, we don't have a DERPMap in LocalBackend yet. In this case,
		// we use the static DERPMap from dnsfallback.
		logf("captivedetection: current DERPMap is empty, using map from dnsfallback")
		derpMap = dnsfallback.GetDERPMap()
	}
	// Use the DERP IPs as captive portal detection endpoints. Using IPs is better than hostnames
	// because they do not depend on DNS resolution.
	for _, region := range derpMap.Regions {
		if region.Avoid {
			continue
		}
		for _, node := range region.Nodes {
			if node.IPv4 == "" || !node.CanPort80 {
				continue
			}
			str := "http://" + node.IPv4 + "/generate_204"
			u, err := url.Parse(str)
			if err != nil {
				logf("captivedetection: failed to parse DERP node URL %q: %v", str, err)
				continue
			}
			p := DERPMapOther
			if region.RegionID == preferredDERPRegionID {
				p = DERPMapPreferred
			}
			e := Endpoint{u, http.StatusNoContent, "", true, p}
			endpoints = append(endpoints, e)
		}
	}

	// Let's also try the default Tailscale coordination server and admin console.
	// These are likely to be blocked on some networks.
	appendTailscaleEndpoint := func(urlString string) {
		u, err := url.Parse(urlString)
		if err != nil {
			logf("captivedetection: failed to parse Tailscale URL %q: %v", urlString, err)
			return
		}
		endpoints = append(endpoints, Endpoint{u, http.StatusNoContent, "", false, Tailscale})
	}
	appendTailscaleEndpoint("http://controlplane.tailscale.com/generate_204")
	appendTailscaleEndpoint("http://login.tailscale.com/generate_204")

	// Sort the endpoints by provider so that we can prioritize DERP nodes in the preferred region, followed by
	// any other DERP server elsewhere, then followed by Tailscale endpoints.
	slices.SortFunc(endpoints, func(x, y Endpoint) int {
		return cmp.Compare(x.Provider, y.Provider)
	})

	return endpoints
}

// responseLooksLikeCaptive checks if the given HTTP response matches the expected response for the Endpoint.
func (e Endpoint) responseLooksLikeCaptive(r *http.Response, logf logger.Logf) bool {
	defer r.Body.Close()

	// Check the status code first.
	if r.StatusCode != e.StatusCode {
		logf("[v1] unexpected status code in captive portal response: want=%d, got=%d", e.StatusCode, r.StatusCode)
		return true
	}

	// If the endpoint supports the Tailscale challenge header, check that the response contains the expected header.
	if e.SupportsTailscaleChallenge {
		expectedResponse := "response ts_" + e.URL.Host
		hasResponse := r.Header.Get("X-Tailscale-Response") == expectedResponse
		if !hasResponse {
			// The response did not contain the expected X-Tailscale-Response header, which means we are most likely
			// behind a captive portal (somebody is tampering with the response headers).
			logf("captive portal check response did not contain expected X-Tailscale-Response header: want=%q, got=%q", expectedResponse, r.Header.Get("X-Tailscale-Response"))
			return true
		}
	}

	// If we don't have an expected content string, we don't need to check the response body.
	if e.ExpectedContent == "" {
		return false
	}

	// Read the response body and check if it contains the expected content.
	b, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		logf("reading captive portal check response body failed: %v", err)
		return false
	}
	hasExpectedContent := mem.Contains(mem.B(b), mem.S(e.ExpectedContent))
	if !hasExpectedContent {
		// The response body did not contain the expected content, that means we are most likely behind a captive portal.
		logf("[v1] captive portal check response body did not contain expected content: want=%q", e.ExpectedContent)
		return true
	}

	// If we got here, the response looks good.
	return false
}

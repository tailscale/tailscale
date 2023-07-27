// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package captiveportal checks whether a captive portal is intercepting
// HTTP(S) traffic.
package captiveportal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"

	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/multierr"
)

var noRedirectClient = &http.Client{
	// No redirects allowed
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},

	// Remaining fields are the same as the default client.
	Transport: http.DefaultClient.Transport,
	Jar:       http.DefaultClient.Jar,
	Timeout:   http.DefaultClient.Timeout,
}

// Check reports whether or not we think the system is behind a captive portal.
func Check(ctx context.Context, logf logger.Logf, dm *tailcfg.DERPMap, preferredDERP int) (bool, error) {
	defer noRedirectClient.CloseIdleConnections()

	node := pickDERPNode(dm, preferredDERP)
	if strings.HasSuffix(node.HostName, tailcfg.DotInvalid) {
		// Don't try to connect to invalid hostnames. This occurred in tests:
		// https://github.com/tailscale/tailscale/issues/6207
		// TODO(bradfitz,andrew-d): how to actually handle this nicely?
		return false, nil
	}

	const numChecks = 2

	type checkResult struct {
		portal bool
		err    error
	}
	results := make(chan checkResult, numChecks)
	mkResult := func(res bool, err error) checkResult { return checkResult{res, err} }

	go func() {
		results <- mkResult(checkGenerate204(ctx, logf, node))
	}()
	go func() {
		results <- mkResult(checkDERPRedirect(ctx, logf, node))
	}()

	var (
		ret  bool
		errs []error
	)
	for i := 0; i < numChecks; i++ {
		res := <-results
		if res.err != nil {
			errs = append(errs, res.err)
			continue
		}
		if res.portal {
			ret = true
		}
	}

	// Ignore errors if we successfully detect a captive portal; just return that.
	if ret {
		return true, nil
	}
	return false, multierr.New(errs...)
}

// checkGenerate204 checks for a captive portal by making a request to the DERP
// node's /generate_204 endpoint with a challenge and verifying that it returns
// a valid response.
func checkGenerate204(ctx context.Context, logf logger.Logf, node *tailcfg.DERPNode) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+node.HostName+"/generate_204", nil)
	if err != nil {
		return false, err
	}

	// Note: the set of valid characters in a challenge and the total
	// length is limited; see isChallengeChar in cmd/derper for more
	// details.
	chal := "ts_" + node.HostName
	req.Header.Set("X-Tailscale-Challenge", chal)
	r, err := noRedirectClient.Do(req)
	if err != nil {
		return false, err
	}
	defer r.Body.Close()

	expectedResponse := "response " + chal
	validResponse := r.Header.Get("X-Tailscale-Response") == expectedResponse

	logf("[v2] checkGenerate204 url=%q status_code=%d valid_response=%v", req.URL.String(), r.StatusCode, validResponse)
	return r.StatusCode != 204 || !validResponse, nil
}

const CaptiveTxtContent = "This is an arbitrary string that we expect the DERP server to return, and use to detect certain kinds of captive portals."

// checkDERPRedirect checks for a captive portal by checking whether a regular
// HTTP request to the DERP node is redirected; this happens on e.g. JetBlue's
// in-flight WiFi.
func checkDERPRedirect(ctx context.Context, logf logger.Logf, node *tailcfg.DERPNode) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+node.HostName, nil)
	if err != nil {
		return false, err
	}

	r, err := noRedirectClient.Do(req)
	if err != nil {
		return false, err
	}
	defer r.Body.Close()

	bodyContent, err := io.ReadAll(r.Body)
	if err != nil {
		return false, fmt.Errorf("reading response body: %v", err)
	}

	// We expect a redirect to the DERP server, or no redirect; if we get
	// redirected anywhere else, assume it's a captive portal.
	location := r.Header.Get("Location")
	logf("[v2] checkDERPRedirect url=%q status_code=%d location=%q", req.URL.String(), r.StatusCode, location)

	// Successful responses aren't captive portals.
	if r.StatusCode == 200 {
		if bytes.Equal(bodyContent, []byte(CaptiveTxtContent)) {
			return false, nil
		}

		// We got an unexpected response body; this is probably
		// something intercepting + rewriting the page.
		return true, nil
	}

	// If we get a non-redirect, the DERP server may be down or something
	// else is wrong, but this probably isn't a captive portal.
	if r.StatusCode < 300 || r.StatusCode > 399 {
		return false, fmt.Errorf("invalid status %d", r.StatusCode)
	}

	// A redirect to the DERP server itself isn't a captive portal, but
	// redirects elsewhere are.
	uri, err := url.Parse(location)
	if err != nil {
		return false, fmt.Errorf("parsing Location: %w", err)
	}

	return uri.Hostname() != node.HostName, nil
}

func pickDERPNode(dm *tailcfg.DERPMap, preferredDERP int) *tailcfg.DERPNode {
	// If we have a preferred DERP region with more than one node, try
	// that; otherwise, pick a random one not marked as "Avoid".
	if preferredDERP == 0 || dm.Regions[preferredDERP] == nil ||
		(preferredDERP != 0 && len(dm.Regions[preferredDERP].Nodes) == 0) {
		rids := make([]int, 0, len(dm.Regions))
		for id, reg := range dm.Regions {
			if reg == nil || reg.Avoid || len(reg.Nodes) == 0 {
				continue
			}
			rids = append(rids, id)
		}
		if len(rids) == 0 {
			return nil
		}
		preferredDERP = rids[rand.Intn(len(rids))]
	}

	return dm.Regions[preferredDERP].Nodes[0]
}

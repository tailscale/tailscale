// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"
)

// rateLimitClient talks to the acme-ratelimit-proxy admin endpoint via
// the kube API server proxy (no port-forward needed).
type rateLimitClient struct {
	hc   *http.Client
	base string
}

func newRateLimitClient(t *testing.T) *rateLimitClient {
	t.Helper()
	hc, err := rest.HTTPClientFor(restCfg)
	if err != nil {
		t.Fatalf("rest HTTPClientFor: %v", err)
	}
	return &rateLimitClient{
		hc: hc,
		base: strings.TrimRight(restCfg.Host, "/") +
			"/api/v1/namespaces/" + ns + "/services/acme-ratelimit:admin/proxy",
	}
}

type rateLimitState struct {
	Total429   int `json:"total429"`
	TotalNew   int `json:"totalNew"`
	TotalRenew int `json:"totalRenew"`
}

// waitReady polls /state until the proxy returns 200 or timeout elapses.
func (c *rateLimitClient) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		resp, err := c.hc.Get(c.base + "/state")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("acme-ratelimit proxy not ready after %v", timeout)
		}
		time.Sleep(3 * time.Second)
	}
}

func (c *rateLimitClient) state(t *testing.T) rateLimitState {
	t.Helper()
	resp, err := c.hc.Get(c.base + "/state")
	if err != nil {
		t.Fatalf("rate-limit state: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("rate-limit state: %v: %s", resp.Status, out)
	}
	var s rateLimitState
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatalf("rate-limit state decode: %v", err)
	}
	return s
}

// set configures the bucket: at most threshold requests per window.
// Retry-After on 429 is the time until the window refills.
func (c *rateLimitClient) set(t *testing.T, threshold int, window time.Duration, reset bool) {
	c.post(t, fmt.Sprintf(`{"threshold":%d,"windowSec":%d,"reset":%t}`,
		threshold, int(window.Seconds()), reset))
}

// reset sets a permissive bucket (10000 per 5min) and clears counters.
func (c *rateLimitClient) reset(t *testing.T) { c.set(t, 10000, 5*time.Minute, true) }

// setDelay holds each forwarded new-order for d before sending it to
// Pebble, simulating ACME latency.
func (c *rateLimitClient) setDelay(t *testing.T, d time.Duration) {
	c.post(t, fmt.Sprintf(`{"delayMs":%d}`, d.Milliseconds()))
}

func (c *rateLimitClient) post(t *testing.T, body string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, c.base+"/set", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("rate-limit POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatalf("rate-limit POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("rate-limit POST %s: %v: %s", body, resp.Status, out)
	}
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/syncs"
	"tailscale.com/tstest/nettest"
	"tailscale.com/util/must"
)

func TestAvailableEndpointsAlwaysAtLeastTwo(t *testing.T) {
	endpoints := availableEndpoints(nil, 0, t.Logf, runtime.GOOS)
	if len(endpoints) == 0 {
		t.Errorf("Expected non-empty AvailableEndpoints, got an empty slice instead")
	}
	if len(endpoints) == 1 {
		t.Errorf("Expected at least two AvailableEndpoints for redundancy, got only one instead")
	}
	for _, e := range endpoints {
		if e.URL.Scheme != "http" {
			t.Errorf("Expected HTTP URL in Endpoint, got HTTPS")
		}
	}
}

// TestProbeSetIncludesHostnameEndpoints guards the property that a detection
// pass always probes by hostname as well as by IP. Portals that intercept on
// the HTTP Host header blackhole the IP-addressed probes, so a probe set made
// up only of those sees nothing at all.
func TestProbeSetIncludesHostnameEndpoints(t *testing.T) {
	endpoints := availableEndpoints(nil, 0, t.Logf, runtime.GOOS)
	probes := probeSet(endpoints)

	var byTier map[Tier]int = map[Tier]int{}
	for _, e := range probes {
		byTier[e.Tier]++
	}
	if got := byTier[TierDERPIP]; got != numDERPIPProbes {
		t.Errorf("probe set has %d TierDERPIP endpoints, want %d", got, numDERPIPProbes)
	}
	if got := byTier[TierHostname]; got != numHostnameProbes {
		t.Errorf("probe set has %d TierHostname endpoints, want %d", got, numHostnameProbes)
	}
	if got := byTier[TierThirdParty]; got != 0 {
		t.Errorf("probe set has %d TierThirdParty endpoints, want 0; they are escalation-only", got)
	}
}

// TestPreferredRegionProbedFirst checks that the probe budget for IP endpoints
// goes to the preferred DERP region when we know it.
func TestPreferredRegionProbedFirst(t *testing.T) {
	endpoints := availableEndpoints(nil, 1, t.Logf, runtime.GOOS)
	probes := probeSet(endpoints)
	if len(probes) == 0 {
		t.Fatal("no probes")
	}
	if got := probes[0].Provider; got != DERPMapPreferred {
		t.Errorf("first probe provider = %v, want %v", got, DERPMapPreferred)
	}
}

func TestDetectCaptivePortalReturnsFalse(t *testing.T) {
	d := NewDetector(t.Logf)
	found := d.Detect(context.Background(), netmon.NewStatic(), nil, 0)
	if found {
		t.Errorf("DetectCaptivePortal returned true, expected false.")
	}
}

func TestEndpointsAreUpAndReturnExpectedResponse(t *testing.T) {
	nettest.SkipIfNoNetwork(t)

	d := NewDetector(t.Logf)
	endpoints := availableEndpoints(nil, 0, t.Logf, runtime.GOOS)
	t.Logf("testing %d endpoints", len(endpoints))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var good atomic.Bool

	var wg sync.WaitGroup
	sem := syncs.NewSemaphore(5)
	for _, e := range endpoints {
		if !e.SupportsTailscaleChallenge {
			// Only the challenge-echoing endpoints can produce a provably
			// clean response, which is what this test is checking for.
			continue
		}
		wg.Add(1)
		go func(endpoint Endpoint) {
			defer wg.Done()

			if !sem.AcquireContext(ctx) {
				return
			}
			defer sem.Release()

			s, _, err := d.probeEndpoint(ctx, endpoint, 0)
			if err != nil && ctx.Err() == nil {
				t.Logf("probeEndpoint failed with endpoint %v: %v", endpoint, err)
			}
			if s != SignalClean {
				t.Logf("probeEndpoint with endpoint %v reported %v, but we aren't behind a captive portal", endpoint, s)
				return
			}
			good.Store(true)
			t.Logf("endpoint good: %v", endpoint)
			cancel()
		}(e)
	}

	wg.Wait()

	if !good.Load() {
		t.Errorf("no good endpoints found")
	}
}

func TestCaptivePortalRequest(t *testing.T) {
	d := NewDetector(t.Logf)
	now := time.Now()
	d.clock = func() time.Time { return now }

	ctx := t.Context()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %q", r.Method)
		}
		if r.URL.Path != "/generate_204" {
			t.Errorf("expected /generate_204, got %q", r.URL.Path)
		}
		q := r.URL.Query()
		if got, want := q.Get("t"), strconv.Itoa(int(now.Unix())); got != want {
			t.Errorf("timestamp param; got %v, want %v", got, want)
		}
		w.Header().Set("X-Tailscale-Response", "response "+r.Header.Get("X-Tailscale-Challenge"))

		w.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()

	e := Endpoint{
		URL:                        must.Get(url.Parse(s.URL + "/generate_204")),
		StatusCode:                 204,
		ExpectedContent:            "",
		SupportsTailscaleChallenge: true,
	}

	got, _, err := d.probeEndpoint(ctx, e, 0)
	if err != nil {
		t.Fatalf("probeEndpoint = %v, %v", got, err)
	}
	if got != SignalClean {
		t.Errorf("probeEndpoint = %v, want %v", got, SignalClean)
	}
}

func TestAgainstDERPHandler(t *testing.T) {
	d := NewDetector(t.Logf)

	ctx := t.Context()

	s := httptest.NewServer(http.HandlerFunc(derpserver.ServeNoContent))
	defer s.Close()
	e := Endpoint{
		URL:                        must.Get(url.Parse(s.URL + "/generate_204")),
		StatusCode:                 204,
		ExpectedContent:            "",
		SupportsTailscaleChallenge: true,
	}
	got, _, err := d.probeEndpoint(ctx, e, 0)
	if err != nil {
		t.Fatalf("probeEndpoint = %v, %v", got, err)
	}
	if got != SignalClean {
		t.Errorf("probeEndpoint = %v, want %v", got, SignalClean)
	}
}

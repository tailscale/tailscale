// Copyright (c) Tailscale Inc & AUTHORS
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
		wg.Add(1)
		go func(endpoint Endpoint) {
			defer wg.Done()

			if !sem.AcquireContext(ctx) {
				return
			}
			defer sem.Release()

			found, err := d.verifyCaptivePortalEndpoint(ctx, endpoint, 0)
			if err != nil && ctx.Err() == nil {
				t.Logf("verifyCaptivePortalEndpoint failed with endpoint %v: %v", endpoint, err)
			}
			if found {
				t.Logf("verifyCaptivePortalEndpoint with endpoint %v says we're behind a captive portal, but we aren't", endpoint)
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	found, err := d.verifyCaptivePortalEndpoint(ctx, e, 0)
	if err != nil {
		t.Fatalf("verifyCaptivePortalEndpoint = %v, %v", found, err)
	}
	if found {
		t.Errorf("verifyCaptivePortalEndpoint = %v, want false", found)
	}
}

func TestAgainstDERPHandler(t *testing.T) {
	d := NewDetector(t.Logf)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := httptest.NewServer(http.HandlerFunc(derpserver.ServeNoContent))
	defer s.Close()
	e := Endpoint{
		URL:                        must.Get(url.Parse(s.URL + "/generate_204")),
		StatusCode:                 204,
		ExpectedContent:            "",
		SupportsTailscaleChallenge: true,
	}
	found, err := d.verifyCaptivePortalEndpoint(ctx, e, 0)
	if err != nil {
		t.Fatalf("verifyCaptivePortalEndpoint = %v, %v", found, err)
	}
	if found {
		t.Errorf("verifyCaptivePortalEndpoint = %v, want false", found)
	}
}

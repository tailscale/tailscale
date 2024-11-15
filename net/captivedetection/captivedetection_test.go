// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"tailscale.com/net/netmon"
	"tailscale.com/syncs"
	"tailscale.com/tstest/nettest"
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

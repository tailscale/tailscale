// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"runtime"
	"sync"
	"testing"

	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/net/netmon"
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

func TestAllEndpointsAreUpAndReturnExpectedResponse(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/13019")
	d := NewDetector(t.Logf)
	endpoints := availableEndpoints(nil, 0, t.Logf, runtime.GOOS)

	var wg sync.WaitGroup
	for _, e := range endpoints {
		wg.Add(1)
		go func(endpoint Endpoint) {
			defer wg.Done()
			found, err := d.verifyCaptivePortalEndpoint(context.Background(), endpoint, 0)
			if err != nil {
				t.Errorf("verifyCaptivePortalEndpoint failed with endpoint %v: %v", endpoint, err)
			}
			if found {
				t.Errorf("verifyCaptivePortalEndpoint with endpoint %v says we're behind a captive portal, but we aren't", endpoint)
			}
		}(e)
	}

	wg.Wait()
}

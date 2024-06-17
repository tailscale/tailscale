// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"testing"

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

func TestAvailableEndpointsUsesAppleOnDarwin(t *testing.T) {
	darwinOK := false
	iosOK := false
	for _, os := range []string{"darwin", "ios"} {
		endpoints := availableEndpoints(nil, 0, t.Logf, os)
		if len(endpoints) == 0 {
			t.Errorf("Expected non-empty AvailableEndpoints, got an empty slice instead")
		}
		u, _ := url.Parse("http://captive.apple.com/hotspot-detect.html")
		want := Endpoint{u, http.StatusOK, "Success", false, Platform}
		for _, e := range endpoints {
			if e.Equal(want) {
				if os == "darwin" {
					darwinOK = true
				} else if os == "ios" {
					iosOK = true
				}
			}
		}
	}

	if !darwinOK || !iosOK {
		t.Errorf("Expected to find Apple captive portal detection URL on both Darwin and iOS, but didn't")
	}
}

func TestAvailableEndpointsUsesMSFTOnWindows(t *testing.T) {
	endpoints := availableEndpoints(nil, 0, t.Logf, "windows")
	if len(endpoints) == 0 {
		t.Errorf("Expected non-empty AvailableEndpoints, got an empty slice instead")
	}
	u, _ := url.Parse("http://www.msftconnecttest.com/connecttest.txt")
	want := Endpoint{u, http.StatusOK, "Microsoft Connect Test", false, Platform}
	for _, e := range endpoints {
		if e.Equal(want) {
			return
		}
	}
	t.Errorf("Expected to find Microsoft captive portal detection URL on Windows, but didn't")
}

func TestDetectCaptivePortalReturnsFalse(t *testing.T) {
	d := NewDetector(t.Logf)
	found := d.Detect(context.Background(), netmon.NewStatic(), nil, 0)
	if found {
		t.Errorf("DetectCaptivePortal returned true, expected false.")
	}
}

func TestAllEndpointsAreUpAndReturnExpectedResponse(t *testing.T) {
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

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"fmt"
	"net"
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
	"tailscale.com/tailcfg"
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

// localDERPMap returns a DERPMap whose nodes are local HTTP servers using
// the given handlers, and a counter of requests they received.
// Callers pass at least five handlers so that detectOnInterface never
// reaches the non-hermetic Tailscale endpoints sorted after DERP nodes.
func localDERPMap(t *testing.T, handlers ...http.HandlerFunc) (*tailcfg.DERPMap, *atomic.Int64) {
	if len(handlers) < 5 {
		t.Fatalf("got %d handlers; want at least 5", len(handlers))
	}
	var hits atomic.Int64
	dm := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}
	for i, h := range handlers {
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			h(w, r)
		}))
		// Endpoints are IPv4-only, so don't let httptest fall back to [::1].
		s.Listener.Close()
		s.Listener = must.Get(net.Listen("tcp4", "127.0.0.1:0"))
		s.Start()
		t.Cleanup(s.Close)
		rid := tailcfg.DERPRegionID(i + 1)
		dm.Regions[rid] = &tailcfg.DERPRegion{
			RegionID: rid,
			Nodes: []*tailcfg.DERPNode{{
				Name:      fmt.Sprintf("%da", rid),
				RegionID:  rid,
				IPv4:      s.Listener.Addr().String(),
				CanPort80: true,
			}},
		}
	}
	return dm, &hits
}

func TestDetectCaptivePortalReturnsFalse(t *testing.T) {
	ok := derpserver.ServeNoContent
	dm, hits := localDERPMap(t, ok, ok, ok, ok, ok)
	d := NewDetector(t.Logf)
	found := d.Detect(t.Context(), netmon.NewStatic(), dm, 0)
	if found {
		t.Errorf("DetectCaptivePortal returned true, expected false.")
	}
	if hits.Load() == 0 {
		t.Skip("no endpoint was reached; no usable non-loopback interface?")
	}
}

func TestDetectCaptivePortalReturnsTrue(t *testing.T) {
	notFound := func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "404 Not Found", http.StatusNotFound)
	}
	ok := derpserver.ServeNoContent
	dm, hits := localDERPMap(t, ok, ok, ok, ok, notFound)
	d := NewDetector(t.Logf)
	found := d.Detect(t.Context(), netmon.NewStatic(), dm, 0)
	if hits.Load() == 0 {
		t.Skip("no endpoint was reached; no usable non-loopback interface?")
	}
	if !found {
		t.Errorf("DetectCaptivePortal returned false, expected true.")
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

	ctx := t.Context()

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

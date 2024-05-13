// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package promvarz

import (
	"expvar"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/expfmt"
	"tailscale.com/tstest"
)

var (
	testVar1 = expvar.NewInt("gauge_promvarz_test_expvar")
	testVar2 = promauto.NewGauge(prometheus.GaugeOpts{Name: "promvarz_test_native"})
)

func TestHandler(t *testing.T) {
	testVar1.Set(42)
	testVar2.Set(4242)

	svr := httptest.NewServer(http.HandlerFunc(Handler))
	defer svr.Close()

	want := `
	# TYPE promvarz_test_expvar gauge
	promvarz_test_expvar 42
	# TYPE promvarz_test_native gauge
	promvarz_test_native 4242
	`
	if err := testutil.ScrapeAndCompare(svr.URL, strings.NewReader(want), "promvarz_test_expvar", "promvarz_test_native"); err != nil {
		t.Error(err)
	}

	// By default, we include Prometheus's process metrics; these are only
	// published on Linux, so check that they're present.
	//
	// If we ever change this behaviour, feel free to change or remove this
	// test; it's only here so that the TestOmitPromethusMetrics test can
	// check that it's working.
	if runtime.GOOS == "linux" && !hasProcessMetrics(t, svr.URL) {
		t.Error("process metrics not found")
	}
}

// TestOmitPromethusMetrics verifies that OmitPromethusMetrics works correctly.
func TestOmitPromethusMetrics(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process metrics are only published on Linux")
	}

	tstest.Replace(t, &OmitPromethusMetrics, true)
	testVar1.Set(42)

	svr := httptest.NewServer(http.HandlerFunc(Handler))
	defer svr.Close()

	want := `
	# TYPE promvarz_test_expvar gauge
	promvarz_test_expvar 42
	`
	if err := testutil.ScrapeAndCompare(svr.URL, strings.NewReader(want), "promvarz_test_expvar"); err != nil {
		t.Error(err)
	}

	if hasProcessMetrics(t, svr.URL) {
		t.Error("process metrics unexpectedly found")
	}
}

// hasProcessMetrics checks if metrics from the Prometheus process collector
// are present at the given metrics URL.
func hasProcessMetrics(tb testing.TB, url string) bool {
	resp, err := http.Get(url)
	if err != nil {
		tb.Errorf("scraping metrics failed: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		tb.Errorf("the scraping target returned a status code other than 200: %d",
			resp.StatusCode)
		return false
	}

	var tp expfmt.TextParser
	metrics, err := tp.TextToMetricFamilies(resp.Body)
	if err != nil {
		tb.Errorf("converting body to metric families failed: %v", err)
		return false
	}
	if _, found := metrics["process_open_fds"]; found {
		return true
	}
	return false
}

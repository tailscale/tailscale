// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package promvarz

import (
	"expvar"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var (
	testVar1 = expvar.NewInt("gauge_promvarz_test_expvar")
	testVar2 = promauto.NewGauge(prometheus.GaugeOpts{Name: "promvarz_test_native"})
)

func TestHandler(t *testing.T) {
	testVar1.Set(42)
	testVar2.Set(4242)

	svr := httptest.NewServer(http.HandlerFunc(handler))
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
}

// TestHandlerQuery checks that requests with varz query parameters
// skip the native metrics, so bad parameters get a clean error and
// filtered output has only what matched.
func TestHandlerQuery(t *testing.T) {
	testVar1.Set(42)

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest("GET", "/debug/varz?match=(", nil))
	if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "promvarz_test_native") {
		t.Errorf("bad match: code %d, body:\n%s", rec.Code, rec.Body.Bytes())
	}

	rec = httptest.NewRecorder()
	handler(rec, httptest.NewRequest("GET", "/debug/varz?match=^promvarz_", nil))
	if got, want := rec.Body.String(), "# TYPE promvarz_test_expvar gauge\npromvarz_test_expvar 42\n"; got != want {
		t.Errorf("match: got %q; want %q", got, want)
	}
}

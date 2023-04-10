// Copyright (c) Tailscale Inc & AUTHORS
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

func TestHandler(t *testing.T) {
	test1 := expvar.NewInt("gauge_promvarz_test_expvar")
	test1.Set(42)
	test2 := promauto.NewGauge(prometheus.GaugeOpts{Name: "promvarz_test_native"})
	test2.Set(4242)

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
}

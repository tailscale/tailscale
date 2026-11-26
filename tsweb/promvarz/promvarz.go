// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package promvarz combines Prometheus metrics exported by our expvar converter
// (tsweb/varz) with metrics exported by the official Prometheus client.
package promvarz

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"tailscale.com/tsweb"
	"tailscale.com/tsweb/varz"
)

func init() {
	tsweb.PrometheusHandler.Set(registerVarz)
}

func registerVarz(debug *tsweb.DebugHandler) {
	debug.Handle("varz", "Metrics (Prometheus)", http.HandlerFunc(handler))
}

// handler returns Prometheus metrics exported by our expvar converter
// and the official Prometheus client.
//
// Requests with a query string, such as varz's "match" and "interval"
// parameters, get only the expvar metrics, so that varz can reject bad
// parameters before writing anything and can stream.
//
// TODO(bradfitz): make match and interval cover the native metrics too,
// perhaps by publishing them as an expvar implementing
// [varz.PrometheusWriter] so varz handles them like any other var.
func handler(w http.ResponseWriter, r *http.Request) {
	if r.URL != nil && r.URL.RawQuery != "" {
		varz.Handler(w, r)
		return
	}
	if err := gatherNativePrometheusMetrics(w); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	varz.Handler(w, r)
}

// gatherNativePrometheusMetrics writes metrics from the default
// metric registry in text format.
func gatherNativePrometheusMetrics(w http.ResponseWriter) error {
	enc := expfmt.NewEncoder(w, expfmt.NewFormat(expfmt.TypeTextPlain))
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return fmt.Errorf("could not gather metrics from DefaultGatherer: %w", err)
	}

	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return fmt.Errorf("could not encode metric %v: %w", mf, err)
		}
	}
	if closer, ok := enc.(expfmt.Closer); ok {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_lowmem_metrics

package localapi

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestLowMemoryMetricsAccessAndSnapshot(t *testing.T) {
	h := new(Handler)
	req := httptest.NewRequest(http.MethodGet, "http://local-tailscaled.sock/localapi/v0/metrics", nil)
	denied := httptest.NewRecorder()
	h.serveMetrics(denied, req)
	if denied.Code != http.StatusForbidden || strings.Contains(denied.Body.String(), "memstats_") {
		t.Fatalf("unauthorized metrics: %d %s", denied.Code, denied.Body.String())
	}
	h.PermitWrite = true
	out := httptest.NewRecorder()
	h.serveMetrics(out, req)
	if out.Code != http.StatusOK {
		t.Fatal(out.Code)
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(out.Body.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			if n, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				values[fields[0]] = n
			}
		}
	}
	if values["goroutines"] == 0 || values["memstats_heap_alloc"] == 0 {
		t.Fatal("missing runtime snapshot")
	}
	if values["memstats_heap_sys"] < values["memstats_heap_inuse"] || values["memstats_heap_inuse"] < values["memstats_heap_alloc"] {
		t.Fatal("inconsistent heap snapshot")
	}
	if _, ok := values["memstats_num_forced_gc"]; !ok {
		t.Fatal("missing forced-GC counter")
	}
}

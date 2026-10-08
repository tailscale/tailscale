// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !wasm

package tsweb

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func TestRuntimeMetricsHandler(t *testing.T) {
	mux := http.NewServeMux()
	Debugger(mux)

	code, _ := get(mux, "/debug/runtime-metrics", pubIP)
	if code != 403 {
		t.Fatalf("/debug/runtime-metrics should be protected; got %d", code)
	}

	code, body := get(mux, "/debug/", tsIP)
	if code != 200 {
		t.Fatalf("/debug/ got %d", code)
	}
	if !strings.Contains(body, "/debug/runtime-metrics") {
		t.Errorf("/debug/ index lacks link to runtime-metrics")
	}

	// A metric that has existed in every Go release since runtime/metrics was added.
	const wantName = "/gc/heap/allocs:bytes"
	// A histogram metric.
	const wantHist = "/sched/pauses/total/gc:seconds"

	t.Run("index", func(t *testing.T) {
		tests := []struct {
			name     string
			accept   string
			query    string
			wantCT   string
			wantBody []string
		}{
			{
				name:     "text_default",
				accept:   "*/*",
				wantCT:   "text/plain; charset=utf-8",
				wantBody: []string{wantName + "\n", wantHist + "\n", "# histogram, cumulative"},
			},
			{
				name:   "html_by_accept",
				accept: "text/html,application/xhtml+xml",
				wantCT: "text/html; charset=utf-8",
				wantBody: []string{
					`<a href="/debug/runtime-metrics` + wantName + `">` + wantName + "</a>",
					"<td>histogram, cumulative</td>",
					`<a href="/debug/runtime-metrics?name=%2A">`,
					// Section header rows link ancestor directories to wildcard queries.
					`<a href="/debug/runtime-metrics?name=%2Fgc%2F%2A">/gc/*</a> <a href="/debug/runtime-metrics?name=%2Fgc%2Fheap%2F%2A">/gc/heap/*</a></td></tr>`,
				},
			},
			{
				name:     "html_by_query",
				accept:   "*/*",
				query:    "?format=html",
				wantCT:   "text/html; charset=utf-8",
				wantBody: []string{"<table>"},
			},
			{
				name:     "text_by_query",
				accept:   "text/html",
				query:    "?format=text",
				wantCT:   "text/plain; charset=utf-8",
				wantBody: []string{wantName + "\n"},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", "/debug/runtime-metrics"+tt.query, nil)
				req.RemoteAddr = tsIP + ":1234"
				req.Header.Set("Accept", tt.accept)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				res := rec.Result()
				if res.StatusCode != 200 {
					t.Fatalf("got %v", res.Status)
				}
				if got := res.Header.Get("Content-Type"); got != tt.wantCT {
					t.Errorf("Content-Type = %q; want %q", got, tt.wantCT)
				}
				body := rec.Body.String()
				for _, want := range tt.wantBody {
					if !strings.Contains(body, want) {
						t.Errorf("body lacks %q", want)
					}
				}
			})
		}

		code, body := get(mux, "/debug/runtime-metrics?format=bogus", tsIP)
		if code != 400 {
			t.Errorf("bogus format: got %d, want 400; body: %s", code, body)
		}
	})

	// getJSON fetches the values for query and decodes the JSON object.
	getJSON := func(t *testing.T, query string) map[string]any {
		t.Helper()
		req := httptest.NewRequest("GET", "/debug/runtime-metrics?"+query, nil)
		req.RemoteAddr = tsIP + ":1234"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		res := rec.Result()
		if res.StatusCode != 200 {
			t.Fatalf("%q: got %v: %s", query, res.Status, rec.Body)
		}
		if got := res.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q; want application/json", got)
		}
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("decoding %q: %v; body: %s", query, err, rec.Body)
		}
		return m
	}

	t.Run("one_value", func(t *testing.T) {
		m := getJSON(t, "name="+wantName)
		if len(m) != 1 {
			t.Fatalf("got %d keys, want 1: %v", len(m), m)
		}
		if v, ok := m[wantName].(float64); !ok || v <= 0 {
			t.Errorf("%s = %v (%T); want positive number", wantName, m[wantName], m[wantName])
		}
	})

	t.Run("several_values", func(t *testing.T) {
		m := getJSON(t, "name="+wantName+"&name=/sched/goroutines:goroutines&name="+wantName)
		if len(m) != 2 {
			t.Fatalf("got %d keys, want 2: %v", len(m), m)
		}
	})

	t.Run("histogram", func(t *testing.T) {
		runtime.GC() // ensure at least one pause sample exists
		m := getJSON(t, "name="+wantHist)
		h, ok := m[wantHist].(map[string]any)
		if !ok {
			t.Fatalf("%s = %T; want object", wantHist, m[wantHist])
		}
		counts, _ := h["counts"].([]any)
		buckets, _ := h["buckets"].([]any)
		if len(counts) == 0 || len(buckets) != len(counts)+1 {
			t.Fatalf("got %d counts, %d buckets", len(counts), len(buckets))
		}
		if got := buckets[0]; got != "-Inf" {
			t.Errorf("first bucket = %v; want \"-Inf\"", got)
		}
		if got := buckets[len(buckets)-1]; got != "+Inf" {
			t.Errorf("last bucket = %v; want \"+Inf\"", got)
		}
		var total float64
		for _, c := range counts {
			total += c.(float64)
		}
		if total == 0 {
			t.Errorf("no histogram samples after runtime.GC")
		}
	})

	t.Run("prefix", func(t *testing.T) {
		m := getJSON(t, "name=/gc/*")
		if len(m) < 2 {
			t.Fatalf("got %d keys, want several: %v", len(m), m)
		}
		for k := range m {
			if !strings.HasPrefix(k, "/gc/") {
				t.Errorf("unexpected key %q", k)
			}
		}
		if _, ok := m[wantName]; !ok {
			t.Errorf("missing %s", wantName)
		}
	})

	t.Run("all", func(t *testing.T) {
		m := getJSON(t, "name=*")
		if len(m) != len(runtimeMetricsDescs()) {
			t.Errorf("got %d keys, want %d", len(m), len(runtimeMetricsDescs()))
		}
	})

	// getBareJSON fetches the path form, which returns a metric's value
	// without the object wrapper.
	getBareJSON := func(t *testing.T, name string) any {
		t.Helper()
		req := httptest.NewRequest("GET", "/debug/runtime-metrics"+name, nil)
		req.RemoteAddr = tsIP + ":1234"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		res := rec.Result()
		if res.StatusCode != 200 {
			t.Fatalf("%q: got %v: %s", name, res.Status, rec.Body)
		}
		if got := res.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q; want application/json", got)
		}
		var v any
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatalf("decoding %q: %v; body: %s", name, err, rec.Body)
		}
		return v
	}

	t.Run("bare_value", func(t *testing.T) {
		if v, ok := getBareJSON(t, wantName).(float64); !ok || v <= 0 {
			t.Errorf("%s = %v; want positive number", wantName, v)
		}
		h, ok := getBareJSON(t, wantHist).(map[string]any)
		if !ok || h["counts"] == nil || h["buckets"] == nil {
			t.Errorf("%s = %v; want histogram object", wantHist, h)
		}
		code, body := get(mux, "/debug/runtime-metrics/bogus:units", tsIP)
		if code != 404 {
			t.Errorf("bare unknown: got %d, want 404; body: %s", code, body)
		}
		code, _ = get(mux, "/debug/runtime-metrics"+wantName, pubIP)
		if code != 403 {
			t.Errorf("bare value should be protected; got %d", code)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		code, body := get(mux, "/debug/runtime-metrics?name=/bogus:units", tsIP)
		if code != 404 {
			t.Errorf("got %d, want 404; body: %s", code, body)
		}
		// An unmatched prefix is not an error; it just yields an empty object.
		if m := getJSON(t, "name=/bogus/*"); len(m) != 0 {
			t.Errorf("got %v; want empty object", m)
		}
	})
}

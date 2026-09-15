// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !wasm

package tsweb

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math"
	"net/http"
	"net/url"
	"runtime/metrics"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// runtimeMetricsDescs returns the descriptions of all supported Go
// runtime/metrics, sorted by name.
var runtimeMetricsDescs = sync.OnceValue(func() []metrics.Description {
	descs := metrics.All()
	slices.SortFunc(descs, func(a, b metrics.Description) int {
		return strings.Compare(a.Name, b.Name)
	})
	return descs
})

// runtimeMetricsSlug is the path under /debug/ where
// runtimeMetricsHandler is registered, both as an exact path and as a
// subtree (with a trailing slash).
const runtimeMetricsSlug = "runtime-metrics"

// runtimeMetricsPath is the full path of the runtime/metrics debug page.
const runtimeMetricsPath = "/debug/" + runtimeMetricsSlug

func init() {
	hookRuntimeMetrics.Set(addRuntimeMetricsHandlers)
}

// addRuntimeMetricsHandlers registers runtimeMetricsHandler on d, both
// at its base path and as a subtree for the per-metric path form.
func addRuntimeMetricsHandlers(d *DebugHandler) {
	d.Handle(runtimeMetricsSlug, "Metrics (Go runtime/metrics)", http.HandlerFunc(runtimeMetricsHandler))
	d.HandleSilent(runtimeMetricsSlug+"/", http.HandlerFunc(runtimeMetricsHandler))
}

// runtimeMetricsHandler serves Go runtime/metrics.
//
// At its base path without a "name" query parameter it serves an index
// of all supported metric names and their descriptions, without reading
// any values. The index is HTML for browsers (requests whose Accept
// header includes text/html) and plain text otherwise; the "format"
// query parameter ("html" or "text") overrides that choice.
//
// With one or more "name" query parameters it reads the named metrics
// and returns them as a JSON object keyed by metric name. A name
// ending in "*" matches all metrics with that prefix, so "name=*"
// returns everything and "name=/gc/*" returns the GC metrics.
//
// A metric name may also be appended to the base path, as in
// /debug/runtime-metrics/gc/heap/allocs:bytes, in which case the
// response is that metric's bare JSON value without the object wrapper.
//
// Histograms are objects with "counts" and "buckets" arrays; infinite
// bucket boundaries are encoded as the strings "-Inf" and "+Inf".
func runtimeMetricsHandler(w http.ResponseWriter, r *http.Request) {
	if rest, ok := strings.CutPrefix(r.URL.Path, runtimeMetricsPath+"/"); ok {
		serveRuntimeMetricValue(w, "/"+rest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if names := r.Form["name"]; len(names) > 0 {
		serveRuntimeMetricsJSON(w, names)
		return
	}

	format := r.FormValue("format")
	if format == "" {
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			format = "html"
		} else {
			format = "text"
		}
	}
	switch format {
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case "text":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	default:
		http.Error(w, "unknown format; want html or text", http.StatusBadRequest)
		return
	}
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	if format == "html" {
		writeRuntimeMetricsIndexHTML(bw)
	} else {
		writeRuntimeMetricsIndexText(bw)
	}
}

// serveRuntimeMetricsJSON reads the metrics matching names (exact
// names, or prefixes ending in "*") and writes them as a JSON object.
func serveRuntimeMetricsJSON(w http.ResponseWriter, names []string) {
	descs := runtimeMetricsDescs()
	var samples []metrics.Sample
	seen := map[string]bool{}
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			samples = append(samples, metrics.Sample{Name: name})
		}
	}
	for _, name := range names {
		if prefix, ok := strings.CutSuffix(name, "*"); ok {
			for _, d := range descs {
				if strings.HasPrefix(d.Name, prefix) {
					add(d.Name)
				}
			}
			continue
		}
		if !runtimeMetricExists(name) {
			http.Error(w, fmt.Sprintf("unknown runtime metric %q", name), http.StatusNotFound)
			return
		}
		add(name)
	}
	metrics.Read(samples)

	obj := make(map[string]any, len(samples))
	for _, s := range samples {
		obj[s.Name] = runtimeMetricValueJSON(s.Value)
	}
	writeJSON(w, obj)
}

// serveRuntimeMetricValue reads the single metric name and writes its
// bare JSON value.
func serveRuntimeMetricValue(w http.ResponseWriter, name string) {
	if !runtimeMetricExists(name) {
		http.Error(w, fmt.Sprintf("unknown runtime metric %q", name), http.StatusNotFound)
		return
	}
	samples := []metrics.Sample{{Name: name}}
	metrics.Read(samples)
	writeJSON(w, runtimeMetricValueJSON(samples[0].Value))
}

func runtimeMetricExists(name string) bool {
	return slices.ContainsFunc(runtimeMetricsDescs(), func(d metrics.Description) bool { return d.Name == name })
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "\t")
	e.Encode(v)
}

// runtimeMetricValueJSON converts v to a value that encoding/json can
// encode. Infinite and NaN floats, which JSON cannot represent, become
// strings.
func runtimeMetricValueJSON(v metrics.Value) any {
	switch v.Kind() {
	case metrics.KindUint64:
		return v.Uint64()
	case metrics.KindFloat64:
		return jsonFloat(v.Float64())
	case metrics.KindFloat64Histogram:
		h := v.Float64Histogram()
		buckets := make([]any, len(h.Buckets))
		for i, b := range h.Buckets {
			buckets[i] = jsonFloat(b)
		}
		return map[string]any{
			"counts":  h.Counts,
			"buckets": buckets,
		}
	default:
		return nil
	}
}

func jsonFloat(f float64) any {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
	return f
}

func runtimeMetricKind(k metrics.ValueKind) string {
	switch k {
	case metrics.KindUint64:
		return "uint64"
	case metrics.KindFloat64:
		return "float64"
	case metrics.KindFloat64Histogram:
		return "histogram"
	default:
		return fmt.Sprintf("kind(%d)", k)
	}
}

func writeRuntimeMetricsIndexText(w io.Writer) {
	fmt.Fprintf(w, "# Go runtime/metrics.\n")
	fmt.Fprintf(w, "# Fetch one bare JSON value with %s/NAME, e.g. %s/gc/heap/allocs:bytes.\n", runtimeMetricsPath, runtimeMetricsPath)
	fmt.Fprintf(w, "# Fetch a JSON object of values with %s?name=NAME (repeatable).\n", runtimeMetricsPath)
	fmt.Fprintf(w, "# A trailing * on a name matches by prefix; name=* returns all values.\n\n")
	for _, d := range runtimeMetricsDescs() {
		fmt.Fprintf(w, "%s\n", d.Name)
		for line := range strings.Lines(d.Description) {
			fmt.Fprintf(w, "    # %s\n", strings.TrimRight(line, "\n"))
		}
		fmt.Fprintf(w, "    # %s", runtimeMetricKind(d.Kind))
		if d.Cumulative {
			fmt.Fprintf(w, ", cumulative")
		}
		fmt.Fprintf(w, "\n\n")
	}
}

func writeRuntimeMetricsIndexHTML(w io.Writer) {
	// valueURL returns the URL serving name's value. Exact metric names
	// are appended to the path and yield a bare JSON value. Wildcards
	// use the name query parameter and yield a JSON object.
	valueURL := func(name string) string {
		if strings.HasSuffix(name, "*") {
			return runtimeMetricsPath + "?name=" + url.QueryEscape(name)
		}
		return runtimeMetricsPath + name
	}
	fmt.Fprintf(w, `<html><head><title>runtime/metrics</title>
<style>
body { font-family: monospace; }
table { border-collapse: collapse; }
td, th { border: 1px solid #ccc; padding: 2px 6px; vertical-align: top; text-align: left; }
.desc { color: #555; }
tr.wild td { background: #eee; }
</style></head><body>
<h1>Go runtime/metrics</h1>
<p>See <a href="https://pkg.go.dev/runtime/metrics">runtime/metrics</a>.
Click a name to read its bare value as JSON. Values are not read for this index.
Append <code>?format=text</code> for a plain text index.
Fetch a JSON object of several values with repeated <code>?name=</code> parameters; a trailing
<code>*</code> matches by prefix (<a href="%s">all values</a>, <a href="%s">GC values</a>).</p>
<table>
<tr><th>Name</th><th>Kind</th><th>Description</th></tr>
`, valueURL("*"), valueURL("/gc/*"))
	var lastDir string
	for _, d := range runtimeMetricsDescs() {
		// Before each run of metrics sharing a directory, emit a row
		// linking each ancestor directory to its wildcard query, so
		// "/gc/heap/allocs:bytes" is preceded by links to "/gc/*" and
		// "/gc/heap/*".
		if dir := d.Name[:strings.LastIndex(d.Name, "/")+1]; dir != lastDir {
			lastDir = dir
			io.WriteString(w, `<tr class="wild"><td colspan="3">`)
			for i := 1; i < len(dir); i++ {
				if dir[i] != '/' {
					continue
				}
				pat := dir[:i+1] + "*"
				fmt.Fprintf(w, ` <a href="%s">%s</a>`, valueURL(pat), html.EscapeString(pat))
			}
			io.WriteString(w, "</td></tr>\n")
		}
		kind := runtimeMetricKind(d.Kind)
		if d.Cumulative {
			kind += ", cumulative"
		}
		fmt.Fprintf(w, `<tr><td><a href="%s">%s</a></td><td>%s</td><td class="desc">%s</td></tr>`+"\n",
			valueURL(d.Name), html.EscapeString(d.Name), kind, html.EscapeString(d.Description))
	}
	io.WriteString(w, "</table></body></html>\n")
}

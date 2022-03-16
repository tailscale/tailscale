// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"expvar"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"runtime"

	"tailscale.com/version"
)

// DebugHandler is an http.Handler that serves a debugging "homepage",
// and provides helpers to register more debug endpoints and reports.
//
// The rendered page consists of three sections: informational
// key/value pairs, links to other pages, and additional
// program-specific HTML. Callers can add to these sections using the
// KV, URL and Section helpers respectively.
//
// Additionally, the Handle method offers a shorthand for correctly
// registering debug handlers and cross-linking them from /debug/.
type DebugHandler struct {
	mux      *http.ServeMux                   // where this handler is registered
	kvs      []func(io.Writer)                // output one <li>...</li> each, see KV()
	urls     []string                         // one <li>...</li> block with link each
	sections []func(io.Writer, *http.Request) // invoked in registration order prior to outputting </body>
}

// Debugger returns the DebugHandler registered on mux at /debug/,
// creating it if necessary.
func Debugger(mux *http.ServeMux) *DebugHandler {
	h, pat := mux.Handler(&http.Request{URL: &url.URL{Path: "/debug/"}})
	if d, ok := h.(*DebugHandler); ok && pat == "/debug/" {
		return d
	}
	ret := &DebugHandler{
		mux: mux,
	}
	mux.Handle("/debug/", ret)

	// Register this one directly on mux, rather than using
	// ret.URL/etc, as we don't need another line of output on the
	// index page. The /pprof/ index already covers it.
	mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))

	ret.KVFunc("Uptime", func() any { return Uptime() })
	ret.KV("Version", version.Long)
	ret.Handle("vars", "Metrics (Go)", expvar.Handler())
	ret.Handle("varz", "Metrics (Prometheus)", http.HandlerFunc(VarzHandler))
	ret.Handle("pprof/", "pprof", http.HandlerFunc(pprof.Index))
	ret.URL("/debug/pprof/goroutine?debug=1", "Goroutines (collapsed)")
	ret.URL("/debug/pprof/goroutine?debug=2", "Goroutines (full)")
	ret.Handle("gc", "force GC", http.HandlerFunc(gcHandler))
	hostname, err := os.Hostname()
	if err == nil {
		ret.KV("Machine", hostname)
	}
	return ret
}

// ServeHTTP implements http.Handler.
func (d *DebugHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !AllowDebugAccess(r) {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	if r.URL.Path != "/debug/" {
		// Sub-handlers are handled by the parent mux directly.
		http.NotFound(w, r)
		return
	}

	f := func(format string, args ...any) { fmt.Fprintf(w, format, args...) }
	f("<html><body><h1>%s debug</h1><ul>", version.CmdName())
	for _, kv := range d.kvs {
		kv(w)
	}
	for _, url := range d.urls {
		io.WriteString(w, url)
	}
	for _, section := range d.sections {
		section(w, r)
	}
}

// Handle registers handler at /debug/<slug> and creates a descriptive
// entry in /debug/ for it.
func (d *DebugHandler) Handle(slug, desc string, handler http.Handler) {
	href := "/debug/" + slug
	d.mux.Handle(href, Protected(handler))
	d.URL(href, desc)
}

// KV adds a key/value list item to /debug/.
func (d *DebugHandler) KV(k string, v any) {
	val := html.EscapeString(fmt.Sprintf("%v", v))
	d.kvs = append(d.kvs, func(w io.Writer) {
		fmt.Fprintf(w, "<li><b>%s:</b> %s</li>", k, val)
	})
}

// KVFunc adds a key/value list item to /debug/. v is called on every
// render of /debug/.
func (d *DebugHandler) KVFunc(k string, v func() any) {
	d.kvs = append(d.kvs, func(w io.Writer) {
		val := html.EscapeString(fmt.Sprintf("%v", v()))
		fmt.Fprintf(w, "<li><b>%s:</b> %s</li>", k, val)
	})
}

// URL adds a URL and description list item to /debug/.
func (d *DebugHandler) URL(url, desc string) {
	if desc != "" {
		desc = " (" + desc + ")"
	}
	d.urls = append(d.urls, fmt.Sprintf(`<li><a href="%s">%s</a>%s</li>`, url, url, html.EscapeString(desc)))
}

// Section invokes f on every render of /debug/ to add supplemental
// HTML to the page body.
func (d *DebugHandler) Section(f func(w io.Writer, r *http.Request)) {
	d.sections = append(d.sections, f)
}

func gcHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("running GC...\n"))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	runtime.GC()
	w.Write([]byte("Done.\n"))
}
